package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// StreamRiskFreshCutoff is required by the incremental worker; absence is a
// hard stop so an old dirty queue cannot silently become current risk state.
func (s *DBStore) StreamRiskFreshCutoff(ctx context.Context, sensor string) (time.Time, error) {
	if s == nil || s.pg == nil || sensor == "" {
		return time.Time{}, errors.New("invalid risk fresh cutoff lookup")
	}
	var cutoff time.Time
	err := s.pg.db.QueryRowContext(ctx, `SELECT accepted_after FROM stream_risk_fresh_cutovers WHERE sensor_id=$1 ORDER BY accepted_after DESC LIMIT 1`, sensor).Scan(&cutoff)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, errors.New("risk fresh cutover has not been audited")
	}
	return cutoff.UTC(), err
}

// StreamRiskCutoverStatus exposes the immutable canceled-work gap alongside
// current pending work. Pending counts are operational state, not completed
// events or evidence that the 5-second event SLA has passed.
type StreamRiskCutoverStatus struct {
	SensorID                     string                   `json:"sensor_id"`
	CancelID                     string                   `json:"cancel_id"`
	AcceptedAfter                time.Time                `json:"accepted_after"`
	CanceledSubjects             int64                    `json:"canceled_subjects"`
	PriorCanceledSubjects        int64                    `json:"prior_canceled_subjects"`
	AuditedAt                    time.Time                `json:"audited_at"`
	PendingSubjects              int64                    `json:"pending_subjects"`
	PendingOlderThan5Sec         int64                    `json:"pending_older_than_5s"`
	OldestPendingAt              *time.Time               `json:"oldest_pending_at,omitempty"`
	SourceGap                    *StreamSourceHistoryGap  `json:"source_gap,omitempty"`
	SourceGaps                   []StreamSourceHistoryGap `json:"source_gaps,omitempty"`
	RouterGap                    *StreamRouterHistoryGap  `json:"router_gap,omitempty"`
	PriorRouterCanceledIndexRows int64                    `json:"prior_router_canceled_index_rows"`
}

type StreamSourceHistoryGap struct {
	Epoch           string    `json:"epoch"`
	SourceOwner     string    `json:"source_owner"`
	CanceledRecords int64     `json:"canceled_records"`
	CanceledBytes   int64     `json:"canceled_bytes"`
	AuditBatches    int64     `json:"audit_batches"`
	ManifestSHA256  string    `json:"manifest_sha256"`
	CutoffAt        time.Time `json:"cutoff_at"`
}

type StreamRouterHistoryGap struct {
	CancelID             string    `json:"cancel_id"`
	IndexedAfter         time.Time `json:"indexed_after"`
	CanceledIndexRows    int64     `json:"canceled_index_rows"`
	PriorProcessedEvents int64     `json:"prior_processed_events"`
	AuditedAt            time.Time `json:"audited_at"`
}

func (s *DBStore) GetStreamRiskCutoverStatus(ctx context.Context, sensor string) (StreamRiskCutoverStatus, bool, error) {
	if s == nil || s.pg == nil {
		return StreamRiskCutoverStatus{}, false, errors.New("risk cutover status store unavailable")
	}
	return s.pg.GetStreamRiskCutoverStatus(ctx, sensor)
}

func (s *PostgresStore) GetStreamRiskCutoverStatus(ctx context.Context, sensor string) (StreamRiskCutoverStatus, bool, error) {
	if s == nil || s.db == nil || sensor == "" {
		return StreamRiskCutoverStatus{}, false, errors.New("invalid risk cutover status lookup")
	}
	status := StreamRiskCutoverStatus{SensorID: sensor}
	err := s.db.QueryRowContext(ctx, `SELECT cancel_id,accepted_after,canceled_subjects,created_at
 FROM stream_risk_fresh_cutovers WHERE sensor_id=$1 ORDER BY accepted_after DESC LIMIT 1`, sensor).
		Scan(&status.CancelID, &status.AcceptedAfter, &status.CanceledSubjects, &status.AuditedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return StreamRiskCutoverStatus{}, false, nil
	}
	if err != nil {
		return StreamRiskCutoverStatus{}, false, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce(sum(canceled_subjects),0)
 FROM stream_risk_fresh_cutovers WHERE sensor_id=$1 AND accepted_after<$2`, sensor, status.AcceptedAfter).
		Scan(&status.PriorCanceledSubjects); err != nil {
		return StreamRiskCutoverStatus{}, false, err
	}
	var oldest sql.NullTime
	err = s.db.QueryRowContext(ctx, `SELECT count(*),
 count(*) FILTER (WHERE GREATEST(first_dirty_at,$2::timestamptz)<now()-interval '5 seconds'),
 min(GREATEST(first_dirty_at,$2::timestamptz))
 FROM risk_feature_dirty_subjects WHERE sensor_id=$1`, sensor, status.AcceptedAfter).
		Scan(&status.PendingSubjects, &status.PendingOlderThan5Sec, &oldest)
	if err != nil {
		return StreamRiskCutoverStatus{}, false, err
	}
	if oldest.Valid {
		value := oldest.Time.UTC()
		status.OldestPendingAt = &value
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.epoch,s.source_owner,c.legacy_cutoff_at,c.cancel_manifest_sha256,
 count(d.legacy_reference),coalesce(sum(d.unprocessed_records),0),coalesce(sum(d.unprocessed_bytes),0)
 FROM stream_source_cutovers c JOIN stream_shared_source_cutovers s ON s.epoch=c.epoch AND s.source_path=c.source_path AND s.state='active'
 JOIN stream_discard_manifest d ON d.epoch=c.epoch AND d.source_kind=c.source_kind AND d.source_path=c.source_path
	  AND d.legacy_kind IN ('unread_device_signal_file_chunk','rotated_closed_device_chunk')
 WHERE c.sensor_id=$1 AND c.state='active' AND s.source_owner IN ('packet-sidecar','handshake-sidecar')
 GROUP BY c.epoch,s.source_owner,c.legacy_cutoff_at,c.cancel_manifest_sha256
	ORDER BY s.source_owner,c.legacy_cutoff_at DESC LIMIT 2`, sensor)
	if err != nil {
		return StreamRiskCutoverStatus{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var gap StreamSourceHistoryGap
		if err := rows.Scan(&gap.Epoch, &gap.SourceOwner, &gap.CutoffAt, &gap.ManifestSHA256, &gap.AuditBatches, &gap.CanceledRecords, &gap.CanceledBytes); err != nil {
			return StreamRiskCutoverStatus{}, false, err
		}
		gap.CutoffAt = gap.CutoffAt.UTC()
		status.SourceGaps = append(status.SourceGaps, gap)
	}
	if err := rows.Err(); err != nil {
		return StreamRiskCutoverStatus{}, false, err
	}
	for i := range status.SourceGaps {
		if status.SourceGaps[i].SourceOwner == "packet-sidecar" {
			status.SourceGap = &status.SourceGaps[i]
			break
		}
	}
	var routerGap StreamRouterHistoryGap
	err = s.db.QueryRowContext(ctx, `SELECT cancel_id,indexed_after,canceled_index_rows,prior_processed_events,created_at FROM stream_router_fresh_cutovers
 WHERE sensor_id=$1 ORDER BY indexed_after DESC LIMIT 1`, sensor).
		Scan(&routerGap.CancelID, &routerGap.IndexedAfter, &routerGap.CanceledIndexRows, &routerGap.PriorProcessedEvents, &routerGap.AuditedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return StreamRiskCutoverStatus{}, false, err
	}
	if err == nil {
		routerGap.IndexedAfter = routerGap.IndexedAfter.UTC()
		routerGap.AuditedAt = routerGap.AuditedAt.UTC()
		status.RouterGap = &routerGap
		if err := s.db.QueryRowContext(ctx, `SELECT coalesce(sum(canceled_index_rows),0) FROM stream_router_fresh_cutovers
 WHERE sensor_id=$1 AND indexed_after<$2`, sensor, routerGap.IndexedAfter).
			Scan(&status.PriorRouterCanceledIndexRows); err != nil {
			return StreamRiskCutoverStatus{}, false, err
		}
	}
	status.AcceptedAfter = status.AcceptedAfter.UTC()
	status.AuditedAt = status.AuditedAt.UTC()
	return status, true, nil
}

// StartStreamRiskFreshCutover audits all pre-cutoff dirty work. It removes only
// rows with no fresh input; a subject dirtied again after the cutoff stays
// queued and is flagged as retained in the immutable audit. The caller must
// pause the previous producer and verify its fixed segments first.
func (s *DBStore) StartStreamRiskFreshCutover(ctx context.Context, sensor, cancelID string, cutoff time.Time) (int64, error) {
	if s == nil || s.pg == nil {
		return 0, errors.New("risk fresh cutover store unavailable")
	}
	return s.pg.StartStreamRiskFreshCutover(ctx, sensor, cancelID, cutoff)
}

func (s *PostgresStore) StartStreamRiskFreshCutover(ctx context.Context, sensor, cancelID string, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil || sensor == "" || cancelID == "" || cutoff.IsZero() ||
		!cutoff.Equal(cutoff.Truncate(time.Microsecond)) || cutoff.After(time.Now().UTC()) {
		return 0, errors.New("invalid risk fresh cutover")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('stream-risk-fresh-cutover'),hashtext($1))`, sensor); err != nil {
		return 0, err
	}
	// Serialize with dirty inserts, then refuse a second cutover for this
	// sensor. The audit and cancellation share the same transaction.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE risk_feature_dirty_subjects IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return 0, err
	}
	var prior time.Time
	err = tx.QueryRowContext(ctx, `SELECT accepted_after FROM stream_risk_fresh_cutovers WHERE sensor_id=$1 ORDER BY accepted_after DESC LIMIT 1 FOR UPDATE`, sensor).Scan(&prior)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err == nil && !cutoff.After(prior) {
		return 0, errors.New("risk fresh cutoff must advance beyond the prior generation")
	}
	var expected, stale int64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE last_dirty_at<$2) FROM risk_feature_dirty_subjects WHERE sensor_id=$1 AND first_dirty_at<$2`, sensor, cutoff.UTC()).Scan(&expected, &stale); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO stream_risk_fresh_cutovers(sensor_id,cancel_id,accepted_after,canceled_subjects)
 VALUES($1,$2,$3,$4)`, sensor, cancelID, cutoff.UTC(), expected)
	if err != nil {
		return 0, err
	}
	if n, affectedErr := result.RowsAffected(); affectedErr != nil || n != 1 {
		return 0, fmt.Errorf("risk cutover header was not inserted: rows=%d err=%v", n, affectedErr)
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO stream_risk_canceled_subjects(cancel_id,sensor_id,subject_type,subject_id,generation,first_dirty_at,last_dirty_at,last_observed_at,fresh_generation_retained)
	 SELECT $2,sensor_id,subject_type,subject_id,generation,first_dirty_at,last_dirty_at,last_observed_at,last_dirty_at>=$3
	FROM risk_feature_dirty_subjects WHERE sensor_id=$1 AND first_dirty_at<$3`, sensor, cancelID, cutoff.UTC())
	if err != nil {
		return 0, err
	}
	audited, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM risk_feature_dirty_subjects WHERE sensor_id=$1 AND last_dirty_at<$2`, sensor, cutoff.UTC())
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != stale || audited != expected {
		return 0, fmt.Errorf("risk cancellation count mismatch: expected=%d stale=%d audited=%d deleted=%d err=%v", expected, stale, audited, deleted, err)
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return audited, nil
}
