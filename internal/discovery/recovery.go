package discovery

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type RecoveryMove struct {
	Batches int64 `json:"batches"`
	Events  int64 `json:"remaining_events"`
	Applied bool  `json:"applied"`
}

// CancelRecovery removes old, unleased work from scheduling without claiming
// that any event was processed. The immutable manifest keeps the original lane,
// offset and error so an operator can audit exactly what was abandoned.
func (r Repository) CancelRecovery(ctx context.Context, id string, cutoff time.Time, limit int, apply bool) (RecoveryMove, error) {
	var out RecoveryMove
	if id == "" || len(id) > 128 || cutoff.IsZero() || cutoff.After(time.Now()) || limit < 1 || limit > 500 {
		return out, fmt.Errorf("invalid cancellation ID, cutoff or limit")
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: !apply})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var conflict bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_cancel_manifest WHERE cancel_id=$1 AND cutoff_at<>$2)`, id, cutoff).Scan(&conflict); err != nil {
		return out, err
	}
	if conflict {
		return out, fmt.Errorf("cancellation ID cutoff conflict")
	}
	if !apply {
		err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(greatest(coalesce(w.selected_event_count,b.event_count)-w.processed_offset,0)),0) FROM discovery_batch_work w JOIN ingest_batches b USING(batch_id) WHERE w.lane IN ('realtime','backfill') AND NOT w.completed AND w.created_at<$1 AND w.lease_until<=now() AND ($2='' OR b.sensor_id=$2)`, cutoff, r.ClaimSensor).Scan(&out.Batches, &out.Events)
		if err != nil {
			return out, err
		}
		return out, tx.Commit()
	}
	err = tx.QueryRowContext(ctx, `WITH selected AS MATERIALIZED (
 SELECT w.batch_id,w.lane,w.processed_offset,w.created_at,w.error,coalesce(w.selected_event_count,b.event_count) AS event_count FROM discovery_batch_work w JOIN ingest_batches b USING(batch_id)
 WHERE w.lane IN ('realtime','backfill') AND NOT w.completed AND w.created_at<$2 AND w.lease_until<=now() AND ($4='' OR b.sensor_id=$4)
 ORDER BY w.created_at,w.batch_id FOR UPDATE OF w SKIP LOCKED LIMIT $3),
 audited AS (INSERT INTO discovery_cancel_manifest(cancel_id,batch_id,cutoff_at,original_lane,original_offset,original_created_at,original_error,remaining_events)
 SELECT $1,batch_id,$2,lane,processed_offset,created_at,error,greatest(event_count-processed_offset,0) FROM selected RETURNING batch_id),
 moved AS (UPDATE discovery_batch_work w SET lane='cancelled' FROM audited a WHERE w.batch_id=a.batch_id RETURNING w.batch_id)
 SELECT count(*),coalesce(sum(greatest(s.event_count-s.processed_offset,0)),0) FROM moved m JOIN selected s USING(batch_id)`, id, cutoff, limit, r.ClaimSensor).Scan(&out.Batches, &out.Events)
	if err != nil {
		return out, err
	}
	out.Applied = true
	return out, tx.Commit()
}

// MoveRecovery keeps original admission, error and offset in an immutable audit
// manifest. Moving a lane is never completion, and leased work is not moved.
func (r Repository) MoveRecovery(ctx context.Context, id string, cutoff time.Time, limit int, apply bool) (RecoveryMove, error) {
	var out RecoveryMove
	if id == "" || len(id) > 128 || cutoff.IsZero() || cutoff.After(time.Now()) || limit < 1 || limit > 500 {
		return out, fmt.Errorf("invalid recovery ID, cutoff or limit")
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: !apply})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var conflict bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_recovery_manifest WHERE recovery_id=$1 AND cutoff_at<>$2)`, id, cutoff).Scan(&conflict); err != nil {
		return out, err
	}
	if conflict {
		return out, fmt.Errorf("recovery ID cutoff conflict")
	}
	if !apply {
		err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(greatest(coalesce(w.selected_event_count,b.event_count)-w.processed_offset,0)),0) FROM discovery_batch_work w JOIN ingest_batches b USING(batch_id) WHERE w.lane='realtime' AND NOT w.completed AND w.created_at<$1 AND w.lease_until<=now() AND ($2='' OR b.sensor_id=$2)`, cutoff, r.ClaimSensor).Scan(&out.Batches, &out.Events)
		if err != nil {
			return out, err
		}
		return out, tx.Commit()
	}
	err = tx.QueryRowContext(ctx, `WITH selected AS MATERIALIZED (
 SELECT w.batch_id,w.lane,w.processed_offset,w.created_at,w.error,coalesce(w.selected_event_count,b.event_count) AS event_count FROM discovery_batch_work w JOIN ingest_batches b USING(batch_id)
 WHERE w.lane='realtime' AND NOT w.completed AND ($4='' OR b.sensor_id=$4) AND w.created_at<$2 AND w.lease_until<=now() ORDER BY w.created_at,w.batch_id FOR UPDATE OF w SKIP LOCKED LIMIT $3),
 audited AS (INSERT INTO discovery_recovery_manifest(recovery_id,batch_id,cutoff_at,original_lane,original_offset,original_created_at,original_error)
 SELECT $1,batch_id,$2,lane,processed_offset,created_at,error FROM selected RETURNING batch_id),
 moved AS (UPDATE discovery_batch_work w SET lane='backfill' FROM audited a WHERE w.batch_id=a.batch_id RETURNING w.batch_id)
 SELECT count(*),coalesce(sum(greatest(s.event_count-s.processed_offset,0)),0) FROM moved m JOIN selected s USING(batch_id)`, id, cutoff, limit, r.ClaimSensor).Scan(&out.Batches, &out.Events)
	if err != nil {
		return out, err
	}
	out.Applied = true
	return out, tx.Commit()
}
