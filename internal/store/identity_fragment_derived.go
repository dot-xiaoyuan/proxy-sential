package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// Fresh HTTP identity input bypasses the legacy normalized_events materialized
// view. This independent lane updates the endpoint/session compatibility rows
// from the same bounded durable fragments after the primary facts are applied.
func (s *DBStore) runIdentityFragmentDerived(ctx context.Context) {
	for ctx.Err() == nil {
		if s.deferIdentityDerivedWork(ctx) {
			continue
		}
		work, cancel := context.WithTimeout(ctx, identityWorkBudget)
		err := s.projectIdentityFragmentDerived(work)
		cancel()
		delay := 20 * time.Millisecond
		if errors.Is(err, sql.ErrNoRows) {
			delay = time.Second
		} else if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "identity fragment derived:", err)
			}
			delay = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (s *DBStore) projectIdentityFragmentDerived(ctx context.Context) (err error) {
	fragment, err := s.pg.claimIdentityDerivedFragment(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			_ = s.pg.reportIdentityDerivedFragmentError(report, fragment, err)
		}
	}()
	segment, _, err := identityFragmentSegment(fragment)
	if err != nil {
		return err
	}
	if s.identitySkipHistory {
		// Endpoint rows commit first so account-session locks cannot block device
		// signals. A retry is safe because these updates are idempotent.
		if err = s.pg.commitIdentityEndpoints(ctx, segment.Events); err != nil {
			return err
		}
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = writeIdentityEventsShapedTx(ctx, tx, segment.Events, !s.identitySkipHistory, !s.identitySkipHistory); err != nil {
		return err
	}
	signals := make([]DeviceSignal, 0, len(segment.Events))
	for _, item := range BuildDeviceInventories("latest-run", segment.Events, nil) {
		signals = append(signals, item.Signals...)
	}
	if err = upsertDeviceSignalFactsBatch(ctx, tx, s.pg.sensorID, signals); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='completed',derived_error='',derived_lease_until=NULL WHERE batch_id=$1 AND first_ordinal=$2 AND derived_lease_epoch=$3 AND derived_state='attempted'`, fragment.BatchID, fragment.First, fragment.DerivedLeaseEpoch)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrIdentityLeaseExpired
	}
	if err = reclaimIdentityFragmentPayload(ctx, tx, []string{fragment.BatchID}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) claimIdentityDerivedFragment(ctx context.Context) (fragment identityExportFragment, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fragment, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT f.batch_id,b.scope_key,b.source,b.stream_epoch,f.archive_month,f.content_sha256,f.key_scheme,f.first_ordinal,f.record_count,b.accepted_at,f.normalized_events FROM identity_ingest_fragments f JOIN identity_ingest_batches b USING(batch_id) WHERE b.protocol_version=2 AND b.sensor_id=$1 AND b.payload_format='fragments' AND b.processed_offset>=f.first_ordinal+f.record_count AND f.derived_state IN ('pending','attempted') AND (f.derived_lease_until IS NULL OR f.derived_lease_until<now()) ORDER BY b.accepted_at,f.batch_id,f.first_ordinal LIMIT 1 FOR UPDATE OF f SKIP LOCKED`, s.sensorID).Scan(&fragment.BatchID, &fragment.Scope, &fragment.Source, &fragment.Epoch, &fragment.Month, &fragment.Hash, &fragment.KeyScheme, &fragment.First, &fragment.Count, &fragment.Accepted, &fragment.Payload)
	if err != nil {
		return fragment, err
	}
	err = tx.QueryRowContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='attempted',derived_lease_epoch=derived_lease_epoch+1,derived_lease_until=now()+interval '70 seconds' WHERE batch_id=$1 AND first_ordinal=$2 RETURNING derived_lease_epoch`, fragment.BatchID, fragment.First).Scan(&fragment.DerivedLeaseEpoch)
	if err != nil {
		return fragment, err
	}
	return fragment, tx.Commit()
}

func (s *PostgresStore) reportIdentityDerivedFragmentError(ctx context.Context, fragment identityExportFragment, cause error) error {
	code := "derived_storage_error"
	permanent := false
	if errors.Is(cause, streamlog.ErrContentConflict) {
		code, permanent = "derived_content_conflict", true
	} else if errors.Is(cause, ErrInvalidIdentityBatch) {
		code, permanent = "derived_invalid_fragment", true
	}
	state := "attempted"
	if permanent {
		state = "failed"
	}
	// Commit may have succeeded while its response was lost. In that case the
	// fragment can already be completed and its temporary payload released;
	// never put that completed generation back into the retry queue.
	_, err := s.db.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state=$4,derived_error=$5,derived_lease_until=CASE WHEN $4='failed' THEN NULL ELSE derived_lease_until END WHERE batch_id=$1 AND first_ordinal=$2 AND derived_lease_epoch=$3 AND derived_state='attempted'`, fragment.BatchID, fragment.First, fragment.DerivedLeaseEpoch, state, code)
	return err
}
