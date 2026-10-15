package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/normalized"
)

// Inbox work budgets. A fixed 2s budget on a congested disk turned every slow commit
// into a rollback and replay: the field logged 6,447 apply timeouts while each batch
// cost 0.4-0.9s regardless of size. The lease must outlive one claim plus one apply so
// a slow but healthy worker is never fenced out mid-batch.
const (
	identityInboxWorkBudget = 30 * time.Second
	identityInboxLease      = 70 * time.Second
	identityInboxBatchMin   = 100
	identityInboxBatchMax   = 2000
)

// nextInboxBatchSize sizes the next claim. Per-batch cost is dominated by fixed round
// trips and the commit fsync, so shrinking below identityInboxBatchMin only lowers
// throughput. Failures halve down to that floor; a fast success doubles back up.
func nextInboxBatchSize(size int, elapsed time.Duration, err error, stable *int) int {
	if err != nil || elapsed >= identityInboxWorkBudget/2 {
		*stable = 0
		return max(identityInboxBatchMin, size/2)
	}
	*stable++
	if elapsed < identityInboxWorkBudget/6 && *stable >= 2 {
		*stable = 0
		return min(identityInboxBatchMax, size*2)
	}
	return size
}
func (s *DBStore) runIdentityInbox(ctx context.Context) {
	size, stable := identityInboxBatchMin, 0
	nextProgress := time.Time{}
	for ctx.Err() == nil {
		claimStarted := time.Now()
		work, cancel := context.WithTimeout(ctx, identityInboxWorkBudget)
		w, err := s.pg.claimIdentityInbox(work, s.pg.sensorID, size)
		cancel()
		claimDuration := time.Since(claimStarted)
		phase := "claim"
		began := time.Now()
		if err == nil {
			phase = "apply"
			work, cancel = context.WithTimeout(ctx, identityInboxWorkBudget)
			err = s.pg.applyIdentityInbox(work, w)
			cancel()
			size = nextInboxBatchSize(size, time.Since(began), err, &stable)
			if err == nil && time.Now().After(nextProgress) {
				fmt.Fprintf(os.Stderr, "identity inbox progress: records=%d claim=%s apply=%s next_batch=%d\n", len(w.Events), claimDuration, time.Since(began), size)
				nextProgress = time.Now().Add(30 * time.Second)
			}
			if err != nil {
				report, stop := context.WithTimeout(ctx, time.Second)
				_, _ = s.pg.db.ExecContext(report, `UPDATE identity_pipeline_scopes SET lease_until=now()+interval '2 seconds',heartbeat_at=now(),last_error=$3 WHERE scope_key=$1 AND lease_epoch=$2`, w.Scope, w.Epoch, "identity_processing_failed")
				stop()
			}
		}
		delay := 20 * time.Millisecond
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Idle liveness only: consumers treat 15 s as stale, so a 5 s refresh keeps the
				// signal while removing four of five writes to the shared scope row.
				health, c := context.WithTimeout(ctx, time.Second)
				_, _ = s.pg.db.ExecContext(health, `UPDATE identity_pipeline_scopes SET heartbeat_at=now() WHERE sensor_id=$1 AND (heartbeat_at IS NULL OR heartbeat_at<now()-interval '5 seconds')`, s.pg.sensorID)
				c()
			}
			delay = time.Second
			if !errors.Is(err, sql.ErrNoRows) && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "identity inbox %s: %v\n", phase, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// Export is independently leased and never holds a PostgreSQL transaction across
// ClickHouse I/O. Repeated delivery uses stable event IDs; consumers are idempotent.
func (s *DBStore) exportIdentityInboxBatch(ctx context.Context) error {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	type exportBatch struct {
		ID    string `json:"batch_id"`
		Epoch int64  `json:"export_epoch"`
		Scope string
		Count int
	}
	rows, err := tx.QueryContext(ctx, `SELECT batch_id,scope_key,export_epoch,normalized_events,records_emitted FROM identity_ingest_batches WHERE protocol_version=2 AND sensor_id=$1 AND export_state<>'completed' AND (export_lease_until IS NULL OR export_lease_until<now()) ORDER BY accepted_at,batch_id FOR UPDATE SKIP LOCKED LIMIT 100`, s.pg.sensorID)
	if err != nil {
		return err
	}
	batches := []exportBatch{}
	events := []normalized.Event{}
	for rows.Next() {
		var batch exportBatch
		var raw []byte
		if err = rows.Scan(&batch.ID, &batch.Scope, &batch.Epoch, &raw, &batch.Count); err != nil {
			break
		}
		var records []normalized.Event
		if err = json.Unmarshal(raw, &records); err != nil {
			break
		}
		if len(records) != batch.Count {
			err = fmt.Errorf("export batch record count mismatch")
			break
		}
		if len(batches) > 0 && len(events)+len(records) > 500 {
			break
		}
		batches = append(batches, batch)
		events = append(events, records...)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(batches) == 0 {
		return sql.ErrNoRows
	}
	rawBatches, err := json.Marshal(batches)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE identity_ingest_batches b SET export_epoch=b.export_epoch+1,export_state='processing',export_lease_until=now()+interval '60 seconds' FROM jsonb_to_recordset($1::jsonb) r(batch_id text,export_epoch bigint) WHERE b.batch_id=r.batch_id AND b.export_epoch=r.export_epoch AND b.export_state<>'completed' AND (b.export_lease_until IS NULL OR b.export_lease_until<now())`, rawBatches)
	if err != nil {
		return err
	}
	claimed, _ := result.RowsAffected()
	if claimed != int64(len(batches)) {
		return ErrIdentityLeaseExpired
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	err = s.ch.WriteNormalizedEvents(ctx, events)
	if err != nil {
		report, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		_, _ = s.pg.db.ExecContext(report, `UPDATE identity_ingest_batches b SET export_state='failed',export_error='raw_export_failed',export_lease_until=now()+interval '5 seconds' FROM jsonb_to_recordset($1::jsonb) r(batch_id text,export_epoch bigint) WHERE b.batch_id=r.batch_id AND b.export_epoch=r.export_epoch+1`, rawBatches)
		scopes := []string{}
		seen := map[string]bool{}
		for _, batch := range batches {
			if !seen[batch.Scope] {
				scopes = append(scopes, batch.Scope)
				seen[batch.Scope] = true
			}
		}
		_, _ = s.pg.db.ExecContext(report, `UPDATE identity_pipeline_scopes SET export_last_error='raw_export_failed',export_heartbeat_at=now() WHERE scope_key=ANY($1::text[])`, scopes)
		return err
	}
	tx, err = s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	updated, err := tx.QueryContext(ctx, `UPDATE identity_ingest_batches b SET export_state='completed',export_error=NULL,export_lease_until=NULL FROM jsonb_to_recordset($1::jsonb) r(batch_id text,export_epoch bigint) WHERE b.batch_id=r.batch_id AND b.export_epoch=r.export_epoch+1 AND b.export_lease_until>now() AND b.export_state<>'completed' RETURNING b.scope_key,b.records_emitted`, rawBatches)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	changed := 0
	for updated.Next() {
		var key string
		var count int
		if err = updated.Scan(&key, &count); err != nil {
			break
		}
		counts[key] += count
		changed++
	}
	if err == nil {
		err = updated.Err()
	}
	updated.Close()
	if err != nil {
		return err
	}
	if changed != len(batches) {
		return ErrIdentityLeaseExpired
	}
	updates := []map[string]any{}
	for key, count := range counts {
		updates = append(updates, map[string]any{"scope_key": key, "records": count})
	}
	rawUpdates, err := json.Marshal(updates)
	if err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE identity_pipeline_scopes p SET export_pending_records=p.export_pending_records-r.records,export_last_error='',export_heartbeat_at=now(),export_completed_at=now() FROM jsonb_to_recordset($1::jsonb) r(scope_key text,records integer) WHERE p.scope_key=r.scope_key`, rawUpdates)
	if err != nil {
		return err
	}
	changedScopes, _ := result.RowsAffected()
	if changedScopes != int64(len(counts)) {
		return ErrIdentityLeaseExpired
	}
	return tx.Commit()
}
func (s *DBStore) runIdentityInboxExport(ctx context.Context) {
	for ctx.Err() == nil {
		// Raw evidence remains durably queued in PostgreSQL. When the authoritative
		// identity lane falls behind, avoid competing ClickHouse writes on the
		// same storage device until current sessions catch up.
		if s.deferIdentityDerivedWork(ctx) {
			continue
		}
		work, cancel := context.WithTimeout(ctx, 45*time.Second)
		err := s.exportIdentityInboxBatch(work)
		cancel()
		if errors.Is(err, sql.ErrNoRows) {
			health, c := context.WithTimeout(ctx, time.Second)
			_, _ = s.pg.db.ExecContext(health, `UPDATE identity_pipeline_scopes SET export_heartbeat_at=now() WHERE sensor_id=$1 AND (export_heartbeat_at IS NULL OR export_heartbeat_at<now()-interval '5 seconds')`, s.pg.sensorID)
			c()
		}
		delay := 20 * time.Millisecond
		if err != nil {
			delay = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}
