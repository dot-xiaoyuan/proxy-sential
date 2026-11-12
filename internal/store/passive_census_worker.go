package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"proxy-sentinel/internal/discovery"
)

type censusPendingBatch struct {
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

func (s *DBStore) applyPassiveCensus(ctx context.Context, task censusPendingBatch) error {
	started := time.Now()
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Two materializer services may run this worker. Serialize one sensor's
	// affected-key writes so late and rebound claims cannot race each other.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('passive-census:'||$1,0))`, task.SensorID); err != nil {
		return err
	}
	var owner string
	if err = tx.QueryRowContext(ctx, `SELECT lease_owner FROM passive_census_pending_batches WHERE id=$1 AND processed_at IS NULL FOR UPDATE`, task.ID).Scan(&owner); err != nil {
		return err
	}
	if owner != task.Owner {
		return fmt.Errorf("census lease changed before projection")
	}
	var written int64
	var changedRows int64
	if changedRows, err = writeCensusJSONChunks(ctx, tx, censusCurrentUpsert, len(task.Payload.Current), func(a, b int) any { return task.Payload.Current[a:b] }); err != nil {
		return err
	}
	written += changedRows
	if changedRows, err = writeCensusJSONChunks(ctx, tx, censusBucketUpsert, len(task.Payload.Buckets), func(a, b int) any { return task.Payload.Buckets[a:b] }); err != nil {
		return err
	}
	written += changedRows
	if changedRows, err = writeCensusJSONChunks(ctx, tx, censusBindingPriorUpdate, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }); err != nil {
		return err
	}
	written += changedRows
	if changedRows, err = writeCensusJSONChunks(ctx, tx, censusBindingUpsert, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }); err != nil {
		return err
	}
	written += changedRows
	if changedRows, err = writeCensusJSONChunks(ctx, tx, censusBindingSupersessionUpdate, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }); err != nil {
		return err
	}
	written += changedRows
	if changedRows, err = writeCensusJSONChunks(ctx, tx, censusBindingConflictRefresh, len(task.Payload.Bindings), func(a, b int) any { return task.Payload.Bindings[a:b] }); err != nil {
		return err
	}
	written += changedRows
	var currentScope string
	if err = tx.QueryRowContext(ctx, `SELECT scope_version FROM passive_census_runtime WHERE sensor_id=$1 FOR UPDATE`, task.SensorID).Scan(&currentScope); err != nil {
		return err
	}
	if currentScope != task.ScopeVersion {
		return fmt.Errorf("census scope changed before projection")
	}
	var pending sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT min(first_source_at) FROM passive_census_pending_batches WHERE sensor_id=$1 AND processed_at IS NULL AND id<>$2`, task.SensorID, task.ID).Scan(&pending); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE passive_census_runtime SET available_from=coalesce(available_from,$2),last_source_at=greatest(last_source_at,$3),last_success_at=now(),oldest_pending_at=$4,last_error='',last_batch_rows=$5,last_batch_ms=$6,updated_at=now()
 WHERE sensor_id=$1 AND scope_version=$7`, task.SensorID, task.FirstEnqueuedAt, task.LastSourceAt, pending, written, int(time.Since(started).Milliseconds()), task.ScopeVersion)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fmt.Errorf("census runtime scope changed during projection")
	}
	_, err = tx.ExecContext(ctx, `UPDATE passive_census_pending_batches SET processed_at=now(),payload='{}'::jsonb,lease_owner='',lease_until='-infinity',last_error='' WHERE id=$1 AND lease_owner=$2`, task.ID, task.Owner)
	if err != nil {
		return err
	}
	return tx.Commit()
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
	owner := fmt.Sprintf("census-%d", os.Getpid())
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
		task, claimed, err := s.claimPassiveCensus(workCtx, owner)
		if err == nil && claimed {
			err = s.applyPassiveCensus(workCtx, task)
		}
		if err != nil && claimed {
			s.failPassiveCensus(workCtx, task, err)
		}
		cancel()
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
