package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const MaxStreamRiskWindow = 7 * 24 * time.Hour

// A live incremental worker renews this lease every 15 seconds. If it stops,
// producers resume queuing every eligible subject after the lease expires.
const streamRiskWindowLease = 45 * time.Second

func riskWindowSeconds(window time.Duration) (int, error) {
	if window < time.Second || window > MaxStreamRiskWindow || window%time.Second != 0 {
		return 0, errors.New("incremental risk window must be a whole number of seconds between 1 second and 7 days")
	}
	return int(window / time.Second), nil
}

// RegisterStreamRiskWindow records the window actually used by a continuous
// incremental worker. It refuses concurrent, different windows and widening
// past a horizon for which old packet wakes may already have been omitted.
func (s *DBStore) RegisterStreamRiskWindow(ctx context.Context, sensor string, window time.Duration) error {
	if s == nil || s.pg == nil || s.pg.db == nil || sensor == "" {
		return errors.New("risk window owner unavailable")
	}
	seconds, err := riskWindowSeconds(window)
	if err != nil {
		return err
	}
	var registered int
	err = s.pg.db.QueryRowContext(ctx, `INSERT INTO stream_risk_window_policies(sensor_id,active_window_seconds,safe_skip_seconds,lease_until)
	VALUES($1,$2,$2,statement_timestamp()+make_interval(secs=>$3))
 ON CONFLICT(sensor_id) DO UPDATE
 SET active_window_seconds=EXCLUDED.active_window_seconds,
     lease_until=EXCLUDED.lease_until,updated_at=statement_timestamp()
 WHERE (stream_risk_window_policies.lease_until<=statement_timestamp()
        OR stream_risk_window_policies.active_window_seconds=EXCLUDED.active_window_seconds)
   AND EXCLUDED.active_window_seconds<=stream_risk_window_policies.safe_skip_seconds
	RETURNING safe_skip_seconds`, sensor, seconds, int(streamRiskWindowLease/time.Second)).Scan(&registered)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("risk window conflicts with a live worker or widens a previously skipped horizon; controlled feature replay is required")
	}
	return err
}

// CheckStreamRiskWindow lets a one-shot incremental worker run without
// creating a producer skip lease. It still rejects an unsafe wider read.
func (s *DBStore) CheckStreamRiskWindow(ctx context.Context, sensor string, window time.Duration) error {
	if s == nil || s.pg == nil || s.pg.db == nil || sensor == "" {
		return errors.New("risk window owner unavailable")
	}
	seconds, err := riskWindowSeconds(window)
	if err != nil {
		return err
	}
	var active, safe int
	var leased bool
	err = s.pg.db.QueryRowContext(ctx, `SELECT active_window_seconds,safe_skip_seconds,lease_until>statement_timestamp()
 FROM stream_risk_window_policies WHERE sensor_id=$1`, sensor).Scan(&active, &safe, &leased)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if seconds > safe || (leased && seconds != active) {
		return fmt.Errorf("risk window %s conflicts with recorded skip horizon or live worker; controlled feature replay is required", window)
	}
	return nil
}
