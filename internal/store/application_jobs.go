package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func appToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func appJob(raw []byte) (appdomain.Job, error) {
	var j appdomain.Job
	err := json.Unmarshal(raw, &j)
	return j, err
}
func (d *applicationDB) State(ctx context.Context) (appdomain.ProcessingStatus, error) {
	s := appdomain.ProcessingStatus{Storage: "database", QueryMillis: d.queryMillis.Load()}
	rows, err := d.store.pg.db.QueryContext(ctx, "SELECT lane,job FROM application_processing_jobs")
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var lane string
		var raw []byte
		if err = rows.Scan(&lane, &raw); err != nil {
			return s, err
		}
		j, e := appJob(raw)
		if e != nil {
			return s, e
		}
		if j.After.Timestamp != "" {
			if t, e := time.Parse(time.RFC3339Nano, j.After.Timestamp); e == nil {
				j.LagSeconds = max(0, time.Since(t).Seconds())
			}
		}
		switch lane {
		case "realtime":
			s.Realtime = j
		case "history":
			s.History = j
		case "reconcile":
			s.Reconcile = j
		}
	}
	return s, rows.Err()
}
func (d *applicationDB) Start(ctx context.Context, now time.Time, version string) error {
	tx, err := d.store.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO application_processing_jobs(lane,job) VALUES('history','{}') ON CONFLICT DO NOTHING"); err != nil {
		return err
	}
	var raw []byte
	var leased bool
	if err = tx.QueryRowContext(ctx, "SELECT job,lease_until>now() FROM application_processing_jobs WHERE lane='history' FOR UPDATE").Scan(&raw, &leased); err != nil {
		return err
	}
	old, err := appJob(raw)
	if err != nil {
		return err
	}
	if leased || old.Status == "running" || old.Status == "paused" || old.RequestedControl != "" {
		return fmt.Errorf("history task is active; resume or cancel it first")
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, "SELECT nextval('application_revision_seq')").Scan(&revision); err != nil {
		return err
	}
	j := appdomain.Job{ID: appToken(), Revision: revision, Status: "running", Version: version, From: now.Add(-7 * 24 * time.Hour), To: now}
	raw, _ = json.Marshal(j)
	if _, err = tx.ExecContext(ctx, "UPDATE application_processing_jobs SET job=$1,lease_owner='',lease_until='-infinity',updated_at=now() WHERE lane='history'", raw); err != nil {
		return err
	}
	return tx.Commit()
}
func (d *applicationDB) Control(ctx context.Context, op string) error {
	tx, err := d.store.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	var leased, pending bool
	err = tx.QueryRowContext(ctx, `SELECT job,lease_until>now(),EXISTS(SELECT 1 FROM application_processing_batches b WHERE b.lane='history' AND b.job_id=j.job->>'id' AND NOT b.committed) FROM application_processing_jobs j WHERE lane='history' FOR UPDATE`).Scan(&raw, &leased, &pending)
	if err != nil {
		return err
	}
	j, err := appJob(raw)
	if err != nil {
		return err
	}
	switch op {
	case "pause":
		if j.Status != "running" {
			return fmt.Errorf("only running jobs can pause")
		}
		j.RequestedControl = "pause"
	case "cancel":
		if j.Status != "running" && j.Status != "paused" && j.Status != "failed" {
			return fmt.Errorf("job is not active")
		}
		j.RequestedControl = "cancel"
	case "resume":
		if j.Status != "paused" && j.Status != "failed" {
			return fmt.Errorf("only paused or failed jobs can resume")
		}
		j.Status = "running"
		j.RequestedControl = ""
		j.Error = ""
	default:
		return fmt.Errorf("unknown operation")
	}
	if !leased && !pending {
		applyAppControl(&j)
	}
	raw, _ = json.Marshal(j)
	if _, err = tx.ExecContext(ctx, "UPDATE application_processing_jobs SET job=$1,updated_at=now() WHERE lane='history'", raw); err != nil {
		return err
	}
	return tx.Commit()
}
func applyAppControl(j *appdomain.Job) {
	switch j.RequestedControl {
	case "pause":
		j.Status = "paused"
	case "cancel":
		j.Status = "cancelled"
	}
	j.RequestedControl = ""
}

type appBatch struct {
	ID   int64
	Rows []appdomain.Observation
	Next appdomain.Job
}

const applicationRealtimeSafetyLag = 15 * time.Second
const applicationRealtimeScanSeconds = 60

func applicationJobUpperBound(lane string, now time.Time) time.Time {
	if lane == "realtime" {
		return now.Add(-applicationRealtimeSafetyLag)
	}
	return now
}

func (d *applicationDB) acquire(ctx context.Context, lane string, now time.Time, version string) (appdomain.Job, string, *appBatch, error) {
	tx, err := d.store.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return appdomain.Job{}, "", nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO application_processing_jobs(lane,job) VALUES($1,'{}') ON CONFLICT DO NOTHING", lane); err != nil {
		return appdomain.Job{}, "", nil, err
	}
	var raw []byte
	var leased bool
	if err = tx.QueryRowContext(ctx, "SELECT job,lease_until>now() FROM application_processing_jobs WHERE lane=$1 FOR UPDATE", lane).Scan(&raw, &leased); err != nil {
		return appdomain.Job{}, "", nil, err
	}
	j, err := appJob(raw)
	if err != nil {
		return j, "", nil, err
	}
	if leased {
		return j, "", nil, nil
	}
	if lane != "realtime" {
		// Serialize low-priority admissions across replicas, without holding a lock
		// over ClickHouse I/O. Realtime never takes this advisory lock.
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(710204)"); err != nil {
			return j, "", nil, err
		}
		var occupied bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM application_processing_jobs WHERE lane<>$1 AND lane<>'realtime' AND lease_until>now())", lane).Scan(&occupied); err != nil {
			return j, "", nil, err
		}
		if occupied {
			return j, "", nil, nil
		}
		var busy bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM application_processing_jobs WHERE lane='realtime' AND ((job->>'status')='running' OR COALESCE(job->>'error','')!=''))`).Scan(&busy); err != nil {
			return j, "", nil, err
		}
		if busy {
			return j, "", nil, nil
		}
	}
	if lane == "history" && j.Status != "running" {
		return j, "", nil, nil
	}
	if j.Status != "running" {
		upperBound := applicationJobUpperBound(lane, now)
		from := upperBound.Add(-7 * 24 * time.Hour)
		if lane == "realtime" {
			from = upperBound.Add(-2 * time.Minute)
			if !j.To.IsZero() {
				from = j.To
			}
			if from.Before(upperBound.Add(-7 * 24 * time.Hour)) {
				from = upperBound.Add(-7 * 24 * time.Hour)
			}
		}
		if lane == "reconcile" && !j.To.IsZero() && now.Sub(j.To) < 5*time.Minute {
			return j, "", nil, nil
		}
		if !from.Before(upperBound) {
			return j, "", nil, nil
		}
		deduplicateUntil := j.DeduplicateUntil
		if !from.Before(deduplicateUntil) {
			deduplicateUntil = time.Time{}
		}
		j = appdomain.Job{ID: appToken(), Status: "running", From: from, To: upperBound, Version: version, LastSuccess: j.LastSuccess, DeduplicateUntil: deduplicateUntil}
	}
	var batch appBatch
	var br, nr []byte
	err = tx.QueryRowContext(ctx, "SELECT id,observations,next_job FROM application_processing_batches WHERE lane=$1 AND job_id=$2 AND NOT committed ORDER BY id LIMIT 1", lane, j.ID).Scan(&batch.ID, &br, &nr)
	var pending *appBatch
	if err == nil {
		if err = json.Unmarshal(br, &batch.Rows); err != nil {
			return j, "", nil, err
		}
		if err = json.Unmarshal(nr, &batch.Next); err != nil {
			return j, "", nil, err
		}
		pending = &batch
	} else if !errors.Is(err, sql.ErrNoRows) {
		return j, "", nil, err
	}
	if pending == nil && j.RequestedControl != "" {
		applyAppControl(&j)
		raw, _ = json.Marshal(j)
		_, err = tx.ExecContext(ctx, "UPDATE application_processing_jobs SET job=$2 WHERE lane=$1", lane, raw)
		if err != nil {
			return j, "", nil, err
		}
		return j, "", nil, tx.Commit()
	}
	owner := appToken()
	raw, _ = json.Marshal(j)
	_, err = tx.ExecContext(ctx, "UPDATE application_processing_jobs SET job=$2,lease_owner=$3,lease_until=now()+interval '90 seconds',updated_at=now() WHERE lane=$1", lane, raw, owner)
	if err != nil {
		return j, "", nil, err
	}
	return j, owner, pending, tx.Commit()
}
func (d *applicationDB) Step(ctx context.Context, lane string, now time.Time, b *appdomain.Bundle) (more bool, resultErr error) {
	if b == nil {
		return false, nil
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	job, owner, pending, err := d.acquire(ctx, lane, now, b.Manifest.Version)
	if err != nil || owner == "" {
		return false, err
	}
	defer func() {
		if resultErr == nil {
			return
		}
		// Failure does not advance the cursor or discard the immutable pending page.
		cleanup, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_, _ = d.store.pg.db.ExecContext(cleanup, `UPDATE application_processing_jobs SET job=jsonb_set(jsonb_set(job,'{error}',to_jsonb($3::text)),'{retries}',to_jsonb(COALESCE((job->>'retries')::int,0)+1)),lease_owner='',lease_until='-infinity',updated_at=now() WHERE lane=$1 AND lease_owner=$2`, lane, owner, resultErr.Error())
	}()
	if pending == nil {
		if lane == "history" && job.Version != b.Manifest.Version {
			return false, fmt.Errorf("task requires application bundle %s", job.Version)
		}
		if lane == "realtime" && job.ScanSeconds <= 0 {
			// A ten-minute source window repeatedly reads a dense campus slice for
			// every keyset page. One-minute windows keep late-arrival coverage while
			// sharply reducing bytes read during sustained catch-up.
			job.ScanSeconds = applicationRealtimeScanSeconds
		}
		scan := job.ScanWindow()
		events, e := d.store.ScanApplicationEvents(ctx, scan)
		if e != nil {
			if applicationScanResourceError(e) && job.ShrinkScanWindow() {
				retryCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				raw, _ := json.Marshal(job)
				// Preserve concurrently requested controls while fencing by lease.
				_, saveErr := d.store.pg.db.ExecContext(retryCtx, `UPDATE application_processing_jobs SET job=$3::jsonb || jsonb_build_object('requested_control',COALESCE(job->>'requested_control','')) WHERE lane=$1 AND lease_owner=$2 AND lease_until>now()`, lane, owner, raw)
				stop()
				if saveErr != nil {
					return false, fmt.Errorf("scan failed: %v; persist retry window: %w", e, saveErr)
				}
			}
			return false, e
		}
		batch := &appBatch{Next: job, Rows: []appdomain.Observation{}}
		for _, event := range events {
			if event.EventID == "" {
				return false, fmt.Errorf("source event lacks event ID")
			}
			batch.Rows = append(batch.Rows, appdomain.Observe(event, b))
			batch.Next.After = appdomain.EventCursor(event)
			batch.Next.Processed++
			if batch.Next.AvailableFrom == "" {
				batch.Next.AvailableFrom = event.Timestamp
			}
			batch.Next.AvailableTo = event.Timestamp
		}
		batch.Next.FinishScanWindow(scan, len(events))
		if job.Revision == 0 && len(batch.Rows) > 0 && applicationNeedsExistingLookup(lane, job, scan) {
			existing, e := d.existing(ctx, batch.Rows)
			if e != nil {
				return false, e
			}
			unseen := make([]appdomain.Observation, 0, len(batch.Rows))
			for _, o := range batch.Rows {
				if !existing[o.Key()] {
					unseen = append(unseen, o)
				}
			}
			batch.Rows = unseen
		}
		raw, _ := json.Marshal(batch.Rows)
		next, _ := json.Marshal(batch.Next)
		after, _ := json.Marshal(struct {
			After appdomain.Cursor `json:"after"`
			From  time.Time        `json:"from"`
			To    time.Time        `json:"to"`
		}{job.After, scan.From, scan.To})
		// Fence preparation by locking the lease row. Never retain this transaction
		// during source reads or result writes.
		tx, e := d.store.pg.db.BeginTx(ctx, nil)
		if e != nil {
			return false, e
		}
		var valid bool
		e = tx.QueryRowContext(ctx, "SELECT lease_owner=$2 AND lease_until>now() FROM application_processing_jobs WHERE lane=$1 FOR UPDATE", lane, owner).Scan(&valid)
		if e != nil || !valid {
			tx.Rollback()
			if e != nil {
				return false, e
			}
			return false, fmt.Errorf("application lease lost before prepare")
		}
		e = tx.QueryRowContext(ctx, "INSERT INTO application_processing_batches(lane,job_id,after_key,observations,next_job) VALUES($1,$2,$3,$4,$5) RETURNING id", lane, job.ID, string(after), raw, next).Scan(&batch.ID)
		if e != nil {
			tx.Rollback()
			return false, e
		}
		if e = tx.Commit(); e != nil {
			return false, e
		}
		pending = batch
	}
	if err = d.write(ctx, pending.Rows, job.Revision, pending.ID); err != nil {
		return false, err
	}
	tx, err := d.store.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var raw []byte
	var valid bool
	if err = tx.QueryRowContext(ctx, "SELECT job,lease_owner=$2 AND lease_until>now() FROM application_processing_jobs WHERE lane=$1 FOR UPDATE", lane, owner).Scan(&raw, &valid); err != nil {
		return false, err
	}
	if !valid {
		return false, fmt.Errorf("application lease lost before cursor commit")
	}
	current, err := appJob(raw)
	if err != nil {
		return false, err
	}
	next := pending.Next
	next.RequestedControl = current.RequestedControl
	// Retries describe consecutive failures. A committed page proves the lane
	// recovered, so retaining the old count would leave a permanent false alarm.
	next.Retries = 0
	next.Error = ""
	next.LastSuccess = time.Now().UTC().Format(time.RFC3339Nano)
	next.BatchMillis = time.Since(started).Milliseconds()
	applyAppControl(&next)
	raw, _ = json.Marshal(next)
	if _, err = tx.ExecContext(ctx, "UPDATE application_processing_jobs SET job=$2,lease_owner='',lease_until='-infinity',updated_at=now() WHERE lane=$1", lane, raw); err != nil {
		return false, err
	}
	// Keep compact batch metadata for diagnosis; committed page bodies no longer
	// need to occupy PostgreSQL. Pending pages are always retained for replay.
	if _, err = tx.ExecContext(ctx, "UPDATE application_processing_batches SET committed=true,observations='[]',next_job='{}' WHERE id=$1", pending.ID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM application_processing_batches WHERE committed AND created_at<now()-interval '7 days'"); err != nil {
		return false, err
	}
	return next.Status == "running", tx.Commit()
}

func applicationNeedsExistingLookup(lane string, job appdomain.Job, scan appdomain.Scan) bool {
	if lane != "realtime" {
		return true
	}
	return !job.DeduplicateUntil.IsZero() && scan.From.Before(job.DeduplicateUntil)
}
