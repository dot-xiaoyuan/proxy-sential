package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
)

const (
	censusGroupMaxJobs  = 16
	censusGroupMaxBytes = 4 << 20
	censusGroupMaxFacts = 8192
)

type censusPendingBatch struct {
	PayloadBytes int

	ID              int64
	SensorID        string
	ScopeVersion    string
	FirstSourceAt   time.Time
	LastSourceAt    time.Time
	FirstEnqueuedAt time.Time
	Owner           string
	Attempts        int
	Payload         censusTaskPayload
}

func (s *DBStore) claimPassiveCensus(ctx context.Context, owner string) (censusPendingBatch, bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return censusPendingBatch{}, false, err
	}
	defer tx.Rollback()
	var task censusPendingBatch
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT id,sensor_id,scope_version,first_source_at,last_source_at,first_enqueued_at,payload,attempts
 FROM passive_census_pending_batches WHERE sensor_id=$1 AND processed_at IS NULL AND lease_until<now()
 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1`, s.pg.sensorID).Scan(&task.ID, &task.SensorID, &task.ScopeVersion, &task.FirstSourceAt, &task.LastSourceAt, &task.FirstEnqueuedAt, &raw, &task.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return censusPendingBatch{}, false, tx.Commit()
	}
	if err != nil {
		return censusPendingBatch{}, false, err
	}
	task.Owner = owner
	_, err = tx.ExecContext(ctx, `UPDATE passive_census_pending_batches SET lease_owner=$2,lease_until=now()+interval '90 seconds',attempts=attempts+1 WHERE id=$1`, task.ID, owner)
	if err != nil {
		return censusPendingBatch{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return censusPendingBatch{}, false, err
	}
	if err = json.Unmarshal(raw, &task.Payload); err != nil {
		return task, true, fmt.Errorf("decode census pending batch %d: %w", task.ID, err)
	}
	return task, true, nil
}

type censusGroupFailure struct {
	TaskID int64
	Err    error
}

func (e *censusGroupFailure) Error() string {
	return fmt.Sprintf("census batch %d: %v", e.TaskID, e.Err)
}
func (e *censusGroupFailure) Unwrap() error   { return e.Err }
func censusFailure(id int64, err error) error { return &censusGroupFailure{TaskID: id, Err: err} }

func censusGroupIDs(tasks []censusPendingBatch) string {
	values := make([]string, len(tasks))
	for i, t := range tasks {
		values[i] = strconv.FormatInt(t.ID, 10)
	}
	return "{" + strings.Join(values, ",") + "}"
}

func validateCensusGroup(tasks []censusPendingBatch) error {
	if len(tasks) == 0 || len(tasks) > censusGroupMaxJobs {
		return fmt.Errorf("census group job bound exceeded")
	}
	seen := map[int64]bool{}
	bytes, facts := 0, 0
	for _, t := range tasks {
		if t.ID <= 0 || seen[t.ID] || t.Owner == "" {
			return censusFailure(t.ID, fmt.Errorf("invalid or duplicate census lease"))
		}
		seen[t.ID] = true
		if t.SensorID != tasks[0].SensorID || t.ScopeVersion != tasks[0].ScopeVersion || t.Owner != tasks[0].Owner {
			return censusFailure(t.ID, fmt.Errorf("mixed census sensor, scope or lease owner"))
		}
		size := t.PayloadBytes
		if size == 0 {
			raw, err := json.Marshal(t.Payload)
			if err != nil {
				return censusFailure(t.ID, err)
			}
			size = len(raw)
		}
		if size < 0 {
			return censusFailure(t.ID, fmt.Errorf("invalid census payload size"))
		}
		bytes += size
		facts += len(t.Payload.Current) + len(t.Payload.Buckets) + len(t.Payload.Bindings)
		if bytes > censusGroupMaxBytes || facts > censusGroupMaxFacts {
			return censusFailure(t.ID, fmt.Errorf("census group byte or fact bound exceeded"))
		}
	}
	return nil
}

// Lock only a bounded metadata page first. JSON bodies are transferred only
// after their actual encoded size and array cardinalities fit both budgets.
func (s *DBStore) claimPassiveCensusGroup(ctx context.Context, owner string) ([]censusPendingBatch, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `WITH ready AS MATERIALIZED (
 SELECT id FROM passive_census_pending_batches WHERE sensor_id=$1 AND processed_at IS NULL AND lease_until<now()
 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 16
)
 SELECT id,sensor_id,scope_version,first_source_at,last_source_at,first_enqueued_at,attempts,
 octet_length(payload::text),jsonb_typeof(payload)='object',
 CASE WHEN coalesce(jsonb_typeof(payload->'current'),'null')='null' THEN 0 WHEN jsonb_typeof(payload->'current')='array' THEN jsonb_array_length(payload->'current') ELSE -1 END,
 CASE WHEN coalesce(jsonb_typeof(payload->'buckets'),'null')='null' THEN 0 WHEN jsonb_typeof(payload->'buckets')='array' THEN jsonb_array_length(payload->'buckets') ELSE -1 END,
 CASE WHEN coalesce(jsonb_typeof(payload->'bindings'),'null')='null' THEN 0 WHEN jsonb_typeof(payload->'bindings')='array' THEN jsonb_array_length(payload->'bindings') ELSE -1 END
 FROM ready JOIN passive_census_pending_batches USING(id) ORDER BY id`, s.pg.sensorID)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		task  censusPendingBatch
		facts int
		valid bool
	}
	candidates := []candidate{}
	for rows.Next() {
		var c candidate
		var a, b, d int
		if err = rows.Scan(&c.task.ID, &c.task.SensorID, &c.task.ScopeVersion, &c.task.FirstSourceAt, &c.task.LastSourceAt, &c.task.FirstEnqueuedAt, &c.task.Attempts, &c.task.PayloadBytes, &c.valid, &a, &b, &d); err != nil {
			rows.Close()
			return nil, err
		}
		c.task.Owner = owner
		c.facts = a + b + d
		c.valid = c.valid && a >= 0 && b >= 0 && d >= 0 && c.task.PayloadBytes >= 0
		candidates = append(candidates, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	tasks := []censusPendingBatch{}
	bytes, facts := 0, 0
	for _, c := range candidates {
		invalid := !c.valid || c.task.PayloadBytes > censusGroupMaxBytes || c.facts > censusGroupMaxFacts
		if invalid {
			if len(tasks) > 0 {
				break
			}
			// Fence and back off a malformed/oversize first job without loading its
			// body. Otherwise it could permanently starve every later valid job.
			result, e := tx.ExecContext(ctx, `UPDATE passive_census_pending_batches SET lease_owner=$2,lease_until=now()+interval '90 seconds',attempts=attempts+1 WHERE id=$1 AND processed_at IS NULL AND lease_until<now()`, c.task.ID, owner)
			if e != nil {
				return nil, e
			}
			n, e := result.RowsAffected()
			if e != nil || n != 1 {
				return nil, fmt.Errorf("census invalid-job lease changed")
			}
			tasks = append(tasks, c.task)
			if e = tx.Commit(); e != nil {
				return tasks, censusFailure(c.task.ID, e)
			}
			return tasks, censusFailure(c.task.ID, fmt.Errorf("queued census payload shape or bound invalid"))
		}
		if bytes+c.task.PayloadBytes > censusGroupMaxBytes || facts+c.facts > censusGroupMaxFacts {
			break
		}
		tasks = append(tasks, c.task)
		bytes += c.task.PayloadBytes
		facts += c.facts
	}
	if len(tasks) == 0 {
		return nil, tx.Commit()
	}
	rows, err = tx.QueryContext(ctx, `UPDATE passive_census_pending_batches SET lease_owner=$2,lease_until=now()+interval '90 seconds',attempts=attempts+1
 WHERE id=ANY($1::bigint[]) AND processed_at IS NULL AND lease_until<now() RETURNING id,payload`, censusGroupIDs(tasks), owner)
	if err != nil {
		return nil, err
	}
	positions := map[int64]int{}
	for i, t := range tasks {
		positions[t.ID] = i
	}
	received := map[int64]bool{}
	var decodeErr error
	for rows.Next() {
		var id int64
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		i, ok := positions[id]
		if !ok || received[id] {
			rows.Close()
			return nil, fmt.Errorf("unexpected census claimed row")
		}
		received[id] = true
		if len(raw) > tasks[i].PayloadBytes {
			decodeErr = censusFailure(id, fmt.Errorf("census payload size changed under lease"))
			continue
		}
		if e := json.Unmarshal(raw, &tasks[i].Payload); e != nil && decodeErr == nil {
			decodeErr = censusFailure(id, fmt.Errorf("decode queued census payload: %w", e))
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(received) != len(tasks) {
		return nil, fmt.Errorf("census lease group incomplete")
	}
	if decodeErr == nil {
		decodeErr = validateCensusGroup(tasks)
	}
	if err = tx.Commit(); err != nil {
		return tasks, censusFailure(tasks[0].ID, err)
	}
	return tasks, decodeErr
}

func applyPassiveCensusFacts(ctx context.Context, tx *sql.Tx, task censusPendingBatch) (int64, error) {
	var written int64
	for _, part := range []struct {
		query  string
		length int
		slice  func(int, int) any
	}{
		{censusCurrentUpsert, len(task.Payload.Current), func(a, b int) any { return task.Payload.Current[a:b] }},
		{censusBucketUpsert, len(task.Payload.Buckets), func(a, b int) any { return task.Payload.Buckets[a:b] }},
		{censusBindingPriorUpdate, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }},
		{censusBindingUpsert, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }},
		{censusBindingSupersessionUpdate, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }},
		{censusBindingConflictRefresh, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }},
	} {
		changed, err := writeCensusJSONChunks(ctx, tx, part.query, part.length, part.slice)
		if err != nil {
			return written, err
		}
		written += changed
	}
	return written, nil
}

func (s *DBStore) applyPassiveCensus(ctx context.Context, task censusPendingBatch) error {
	return s.applyPassiveCensusGroup(ctx, []censusPendingBatch{task})
}

func (s *DBStore) applyPassiveCensusGroup(ctx context.Context, tasks []censusPendingBatch) error {
	started := time.Now()
	if err := validateCensusGroup(tasks); err != nil {
		return err
	}
	tasks = append([]censusPendingBatch(nil), tasks...)
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('passive-census:'||$1,0))`, tasks[0].SensorID); err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,lease_owner,sensor_id,scope_version FROM passive_census_pending_batches
 WHERE id=ANY($1::bigint[]) AND processed_at IS NULL ORDER BY id FOR UPDATE`, censusGroupIDs(tasks))
	if err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	wanted := map[int64]censusPendingBatch{}
	for _, t := range tasks {
		wanted[t.ID] = t
	}
	seen := map[int64]bool{}
	var leaseErr error
	for rows.Next() {
		var id int64
		var owner, sensor, scope string
		if err = rows.Scan(&id, &owner, &sensor, &scope); err != nil {
			rows.Close()
			return censusFailure(tasks[0].ID, err)
		}
		t, ok := wanted[id]
		seen[id] = true
		if !ok || owner != t.Owner || sensor != t.SensorID || scope != t.ScopeVersion {
			leaseErr = censusFailure(id, fmt.Errorf("census lease or scope changed before projection"))
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	if leaseErr != nil {
		return leaseErr
	}
	for _, t := range tasks {
		if !seen[t.ID] {
			return censusFailure(t.ID, fmt.Errorf("census job already completed or removed"))
		}
	}
	var currentScope string
	if err = tx.QueryRowContext(ctx, `SELECT scope_version FROM passive_census_runtime WHERE sensor_id=$1 FOR UPDATE`, tasks[0].SensorID).Scan(&currentScope); err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	if currentScope != tasks[0].ScopeVersion {
		return censusFailure(tasks[0].ID, fmt.Errorf("census scope changed before projection"))
	}
	var written int64
	first, last := tasks[0].FirstEnqueuedAt, tasks[0].LastSourceAt
	for _, t := range tasks {
		n, e := applyPassiveCensusFacts(ctx, tx, t)
		if e != nil {
			return censusFailure(t.ID, e)
		}
		written += n
		if t.FirstEnqueuedAt.Before(first) {
			first = t.FirstEnqueuedAt
		}
		if t.LastSourceAt.After(last) {
			last = t.LastSourceAt
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE passive_census_pending_batches SET processed_at=now(),payload='{}'::jsonb,lease_owner='',lease_until='-infinity',last_error=''
 WHERE id=ANY($1::bigint[]) AND lease_owner=$2 AND processed_at IS NULL`, censusGroupIDs(tasks), tasks[0].Owner)
	if err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != int64(len(tasks)) {
		return censusFailure(tasks[0].ID, fmt.Errorf("census completion lease changed"))
	}
	var pending sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT min(first_source_at) FROM passive_census_pending_batches WHERE sensor_id=$1 AND processed_at IS NULL`, tasks[0].SensorID).Scan(&pending); err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	result, err = tx.ExecContext(ctx, `UPDATE passive_census_runtime SET available_from=least(coalesce(available_from,$2),$2),last_source_at=greatest(last_source_at,$3),last_success_at=now(),oldest_pending_at=$4,last_error='',last_batch_rows=$5,last_batch_ms=$6,updated_at=now()
 WHERE sensor_id=$1 AND scope_version=$7`, tasks[0].SensorID, first, last, pending, written, int(time.Since(started).Milliseconds()), tasks[0].ScopeVersion)
	if err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	n, err = result.RowsAffected()
	if err != nil || n != 1 {
		return censusFailure(tasks[0].ID, fmt.Errorf("census runtime scope changed during projection"))
	}
	if err = tx.Commit(); err != nil {
		return censusFailure(tasks[0].ID, err)
	}
	return nil
}

func (s *DBStore) failPassiveCensusGroup(ctx context.Context, tasks []censusPendingBatch, cause error) {
	if len(tasks) == 0 {
		return
	}
	failed := tasks[0].ID
	var failure *censusGroupFailure
	if errors.As(cause, &failure) {
		failed = failure.TaskID
	}
	var retry []censusPendingBatch
	var failedTask *censusPendingBatch
	for i := range tasks {
		if tasks[i].ID == failed {
			failedTask = &tasks[i]
		} else {
			retry = append(retry, tasks[i])
		}
	}
	if failedTask == nil {
		failedTask = &tasks[0]
		retry = tasks[1:]
	}
	// Only the identified failure is delayed. Other jobs retain their complete
	// payload and original enqueue/source times; no completion or cursor advance.
	if len(retry) > 0 {
		report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		_, err := s.pg.db.ExecContext(report, `UPDATE passive_census_pending_batches SET lease_owner='',lease_until='-infinity'
 WHERE id=ANY($1::bigint[]) AND lease_owner=$2 AND processed_at IS NULL`, censusGroupIDs(retry), tasks[0].Owner)
		cancel()
		if err != nil {
			log.Printf("passive census retry lease release failed: %v", err)
		}
	}
	s.failPassiveCensus(ctx, *failedTask, cause)
}

func (s *DBStore) failPassiveCensus(ctx context.Context, task censusPendingBatch, cause error) {
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	message := cause.Error()
	if len(message) > 512 {
		message = message[:512]
	}
	delay := min(time.Hour, 5*time.Second*time.Duration(1<<min(task.Attempts, 10)))
	_, _ = s.pg.db.ExecContext(reportCtx, `UPDATE passive_census_pending_batches SET lease_owner='',lease_until=now()+$4::interval,last_error=$3 WHERE id=$1 AND lease_owner=$2`, task.ID, task.Owner, message, delay.String())
	_, _ = s.pg.db.ExecContext(reportCtx, `UPDATE passive_census_runtime SET failed_batches=failed_batches+1,last_error=$2,oldest_pending_at=least(coalesce(oldest_pending_at,$3),$3),updated_at=now() WHERE sensor_id=$1`, task.SensorID, message, task.FirstSourceAt)
}

func (s *DBStore) runPassiveCensusProjection(ctx context.Context) {
	if os.Getenv("PROXY_SENTINEL_PASSIVE_CENSUS_ENABLED") != "true" {
		return
	}
	ownerPrefix := fmt.Sprintf("census-%d", os.Getpid())
	lastExpiryCheck := time.Time{}
	lastCleanup := time.Time{}
	for ctx.Err() == nil {
		if time.Since(lastCleanup) > time.Minute {
			lastCleanup = time.Now()
			if err := s.cleanupPassiveCensus(ctx); err != nil && ctx.Err() == nil {
				log.Printf("passive census retention cleanup failed: %v", err)
			}
		}
		if time.Since(lastExpiryCheck) > time.Minute {
			lastExpiryCheck = time.Now()
			if err := s.refreshDueCensusTerminals(ctx); err != nil && ctx.Err() == nil {
				log.Printf("passive census expiry refresh failed: %v", err)
			}
		}
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		started := time.Now()
		owner := fmt.Sprintf("%s-%d", ownerPrefix, started.UnixNano())
		tasks, err := s.claimPassiveCensusGroup(workCtx, owner)
		claimed := len(tasks) > 0
		claimedAt := time.Now()
		if err == nil && claimed {
			err = s.applyPassiveCensusGroup(workCtx, tasks)
		}
		completedAt := time.Now()
		if err != nil && claimed {
			s.failPassiveCensusGroup(workCtx, tasks, err)
		}
		cancel()
		if claimed {
			bytes, facts := 0, 0
			for _, task := range tasks {
				bytes += task.PayloadBytes
				facts += len(task.Payload.Current) + len(task.Payload.Buckets) + len(task.Payload.Bindings)
			}
			log.Printf("passive census group jobs=%d bytes=%d facts=%d claim_ms=%d apply_ms=%d total_ms=%d failed=%t", len(tasks), bytes, facts, claimedAt.Sub(started).Milliseconds(), completedAt.Sub(claimedAt).Milliseconds(), completedAt.Sub(started).Milliseconds(), err != nil)
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("passive census projection failed: %v", err)
		}
		if !claimed || err != nil {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func (s *DBStore) cleanupPassiveCensus(ctx context.Context) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, query := range []string{
		`DELETE FROM passive_census_identifier_5m WHERE ctid IN (SELECT ctid FROM passive_census_identifier_5m WHERE bucket_at<now()-interval '30 days' ORDER BY bucket_at LIMIT 5000 FOR UPDATE SKIP LOCKED)`,
		`DELETE FROM passive_census_pending_batches WHERE ctid IN (SELECT ctid FROM passive_census_pending_batches WHERE processed_at<now()-interval '7 days' ORDER BY processed_at LIMIT 5000 FOR UPDATE SKIP LOCKED)`,
	} {
		if _, err := s.pg.db.ExecContext(cleanupCtx, query); err != nil {
			return err
		}
	}
	return nil
}

func (s *DBStore) refreshDueCensusTerminals(ctx context.Context) error {
	probe, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := s.pg.db.QueryContext(probe, `SELECT DISTINCT device_key FROM passive_census_terminal_current WHERE sensor_id=$1 AND effective_until<=now() AND classification_status<>'expired' ORDER BY device_key LIMIT 500`, s.pg.sensorID)
	if err != nil {
		return err
	}
	keys := []string{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	return discovery.RefreshCensusTerminals(probe, s.pg.db, s.pg.sensorID, keys)
}
