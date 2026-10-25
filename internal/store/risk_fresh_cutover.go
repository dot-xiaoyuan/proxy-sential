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
