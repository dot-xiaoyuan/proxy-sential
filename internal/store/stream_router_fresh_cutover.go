package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

// StartStreamRouterFreshCutover excludes pre-cutoff index rows from the new
// recognizer. The source must be paused and all earlier search inserts settled.
func (s *DBStore) StartStreamRouterFreshCutover(ctx context.Context, sensor, cancelID string, cutoff time.Time) (uint64, error) {
	if s == nil || s.pg == nil || s.pg.db == nil || s.ch == nil || sensor == "" || cancelID == "" || cutoff.IsZero() ||
		!cutoff.Equal(cutoff.Truncate(time.Microsecond)) || cutoff.After(time.Now().UTC()) {
		return 0, errors.New("invalid router fresh cutover")
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('stream-router-fresh-cutover'),hashtext($1))`, sensor); err != nil {
		return 0, err
	}
	var prior sql.NullTime
	var leased bool
	var processed int64
	err = tx.QueryRowContext(ctx, `SELECT fresh_cutoff_at,lease_until>now(),processed_events FROM stream_router_recognition_state WHERE sensor_id=$1 FOR UPDATE`, sensor).Scan(&prior, &leased, &processed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if leased || (prior.Valid && !cutoff.After(prior.Time)) {
		return 0, errors.New("router recognizer is leased or fresh cutoff did not advance")
	}
	stamp := "parseDateTime64BestEffort(" + chQuote(cutoff.UTC().Format(time.RFC3339Nano)) + ",6)"
	lower := ""
	if prior.Valid {
		lower = "indexed_at>=parseDateTime64BestEffort(" + chQuote(prior.Time.UTC().Format(time.RFC3339Nano)) + ",6) AND "
	}
	query := fmt.Sprintf(`SELECT countIf(%sindexed_at<%s),countIf(indexed_at>=%s) FROM stream_router_signal_index
	 WHERE sensor_id=%s SETTINGS max_threads=1,max_execution_time=10 FORMAT TSV`, lower, stamp, stamp, chQuote(sensor))
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), "\t")
	if len(parts) != 2 {
		return 0, errors.New("invalid router index cutover counts")
	}
	oldRows, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, err
	}
	newRows, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || newRows != 0 {
		return 0, fmt.Errorf("router fresh cutover crosses %d new index rows: %v", newRows, err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO stream_router_fresh_cutovers(sensor_id,cancel_id,indexed_after,canceled_index_rows,prior_processed_events)
 VALUES($1,$2,$3,$4,$5)`, sensor, cancelID, cutoff.UTC(), oldRows, processed); err != nil {
		return 0, err
	}
	if prior.Valid {
		result, updateErr := tx.ExecContext(ctx, `UPDATE stream_router_recognition_state SET fresh_cutoff_at=$2,cancel_id=$3,cursor_indexed_at=$2,cursor_event_key='',lease_owner='',lease_until='-infinity',rule_version=$4,last_success_at=NULL,last_error='',updated_at=now()
 WHERE sensor_id=$1 AND lease_until<now()`, sensor, cutoff.UTC(), cancelID, fingerprint.DefaultRouterRuleSet().Version)
		if updateErr != nil {
			return 0, updateErr
		}
		changed, affectedErr := result.RowsAffected()
		if affectedErr != nil || changed != 1 {
			return 0, fmt.Errorf("router fresh cursor reseed failed: rows=%d err=%v", changed, affectedErr)
		}
	} else if _, err = tx.ExecContext(ctx, `INSERT INTO stream_router_recognition_state(sensor_id,fresh_cutoff_at,cancel_id,cursor_indexed_at,cursor_event_key,rule_version)
 VALUES($1,$2,$3,$2,'',$4)`, sensor, cutoff.UTC(), cancelID, fingerprint.DefaultRouterRuleSet().Version); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return oldRows, nil
}
