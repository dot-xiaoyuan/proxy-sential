package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// A terminal key was removed or an older worker's still-live lease was
// rescheduled. The caller can continue with another key without treating the
// original fragment as completed.
var errIdentityDerivedReadyDeferred = errors.New("identity derived ready key deferred")

// Unattempted rows use -infinity. One ascending range let a continuous supply
// of those rows starve expired leases forever. Probe both index ranges with
// fixed limits and give already-due retries the first opportunity.
const identityDerivedReadyCandidateSQL = `WITH candidates AS MATERIALIZED (
 (SELECT batch_id,first_ordinal,available_at,accepted_at,0 AS retry_rank
  FROM identity_derived_ready
  WHERE sensor_id=$1 AND priority=$2 AND available_at>'-infinity' AND available_at<=now()
  ORDER BY available_at,accepted_at,batch_id,first_ordinal LIMIT 8)
 UNION ALL
 (SELECT batch_id,first_ordinal,available_at,accepted_at,1 AS retry_rank
  FROM identity_derived_ready
  WHERE sensor_id=$1 AND priority=$2 AND available_at='-infinity'
  ORDER BY accepted_at,batch_id,first_ordinal LIMIT 24)
)
SELECT f.batch_id,f.first_ordinal,f.derived_state,f.derived_lease_until,
 COALESCE(f.derived_lease_until>now(),false),b.processed_offset,f.record_count,
 (b.protocol_version=2 AND b.payload_format='fragments' AND b.sensor_id=$1)
FROM candidates c JOIN identity_ingest_fragments f USING(batch_id,first_ordinal)
 JOIN identity_ingest_batches b USING(batch_id)
ORDER BY c.retry_rank,c.available_at,c.accepted_at,c.batch_id,c.first_ordinal
LIMIT 1 FOR UPDATE OF f SKIP LOCKED`

// claimIdentityDerivedReady first limits the compact queue to 32 keys, then
// locks a fragment before modifying the ready key. Completion and terminal
// cleanup also take the fragment lock first. Only a valid leased fragment has
// its original payload read. The existing fragment epoch fences old workers.
func (s *PostgresStore) claimIdentityDerivedReady(ctx context.Context, priority int) (fragment identityExportFragment, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fragment, err
	}
	defer tx.Rollback()
	fragment, err = s.claimIdentityDerivedReadyTx(ctx, tx, priority, nil)
	if err != nil && !errors.Is(err, errIdentityDerivedReadyDeferred) && !errors.Is(err, errIdentityDerivedReadyIneligible) {
		return fragment, err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return identityExportFragment{}, commitErr
	}
	return fragment, err
}

func (s *PostgresStore) claimIdentityDerivedReadyTx(ctx context.Context, tx *sql.Tx, priority int, budget *identityDerivedBatchBudget) (fragment identityExportFragment, err error) {
	if priority != 0 && priority != 1 {
		return fragment, errors.New("invalid identity derived ready priority")
	}
	var batch, state string
	var first, offset, count int
	var lease sql.NullTime
	var active, valid bool
	err = tx.QueryRowContext(ctx, identityDerivedReadyCandidateSQL, s.sensorID, priority).Scan(&batch, &first, &state, &lease, &active, &offset, &count, &valid)
	if err != nil {
		return fragment, err
	}
	if state == "completed" || state == "failed" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM identity_derived_ready WHERE batch_id=$1 AND first_ordinal=$2`, batch, first); err != nil {
			return fragment, err
		}
		return fragment, errIdentityDerivedReadyDeferred
	}
	if !valid || (state != "pending" && state != "attempted") || count < 1 || count > 50 || first < 0 || offset < first+count {
		// Preserve and report the bad key, but delay its next attempt so one
		// inconsistent row does not block every later ready fragment.
		result, updateErr := tx.ExecContext(ctx, `UPDATE identity_derived_ready SET available_at=now()+interval '30 seconds',last_error=$3 WHERE batch_id=$1 AND first_ordinal=$2`, batch, first, "identity_ready_not_eligible")
		if updateErr != nil {
			return fragment, updateErr
		}
		if changed, rowsErr := result.RowsAffected(); rowsErr != nil {
			return fragment, rowsErr
		} else if changed != 1 {
			return fragment, errors.New("identity derived ready key disappeared during deferral")
		}
		return fragment, fmt.Errorf("%w: batch=%s ordinal=%d", errIdentityDerivedReadyIneligible, batch, first)
	}
	if active {
		if !lease.Valid {
			return fragment, errors.New("identity derived lease has no expiry")
		}
		if err = updateIdentityDerivedReadyDue(ctx, tx, batch, first, lease.Time); err != nil {
			return fragment, err
		}
		return fragment, errIdentityDerivedReadyDeferred
	}
	if budget != nil {
		if count > budget.Records {
			return fragment, errIdentityDerivedBatchFull
		}
		var bytes int
		if err = tx.QueryRowContext(ctx, `SELECT octet_length(COALESCE(normalized_events::text,'')) FROM identity_ingest_fragments WHERE batch_id=$1 AND first_ordinal=$2`, batch, first).Scan(&bytes); err != nil {
			return fragment, err
		}
		if bytes > budget.Bytes {
			return fragment, errIdentityDerivedBatchFull
		}
	}
	var until sql.NullTime
	err = tx.QueryRowContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='attempted',derived_lease_epoch=derived_lease_epoch+1,derived_lease_until=now()+interval '70 seconds' WHERE batch_id=$1 AND first_ordinal=$2 RETURNING derived_lease_epoch,derived_lease_until`, batch, first).Scan(&fragment.DerivedLeaseEpoch, &until)
	if err != nil {
		return fragment, err
	}
	if !until.Valid {
		return fragment, errors.New("identity derived lease update has no expiry")
	}
	if err = updateIdentityDerivedReadyDue(ctx, tx, batch, first, until.Time); err != nil {
		return fragment, err
	}
	err = tx.QueryRowContext(ctx, `SELECT f.batch_id,b.scope_key,b.source,b.stream_epoch,f.archive_month,f.content_sha256,f.key_scheme,f.first_ordinal,f.record_count,b.accepted_at,f.normalized_events
 FROM identity_ingest_fragments f JOIN identity_ingest_batches b USING(batch_id)
 WHERE f.batch_id=$1 AND f.first_ordinal=$2`, batch, first).Scan(&fragment.BatchID, &fragment.Scope, &fragment.Source, &fragment.Epoch, &fragment.Month, &fragment.Hash, &fragment.KeyScheme, &fragment.First, &fragment.Count, &fragment.Accepted, &fragment.Payload)
	if err != nil {
		return fragment, err
	}
	return fragment, err
}

func updateIdentityDerivedReadyDue(ctx context.Context, tx *sql.Tx, batch string, first int, until time.Time) error {
	result, err := tx.ExecContext(ctx, `UPDATE identity_derived_ready SET available_at=$3,last_error='' WHERE batch_id=$1 AND first_ordinal=$2`, batch, first, until)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return err
	} else if changed != 1 {
		return errors.New("identity derived ready key disappeared during claim")
	}
	return nil
}
