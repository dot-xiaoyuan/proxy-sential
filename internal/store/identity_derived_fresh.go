package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

func (s *PostgresStore) loadIdentityDerivedCutover(ctx context.Context, id string) error {
	var after time.Time
	err := s.db.QueryRowContext(ctx, `SELECT accepted_after FROM identity_derived_fresh_starts WHERE cancel_id=$1 AND sensor_id=$2 AND accepted_after<=clock_timestamp()`, id, s.sensorID).Scan(&after)
	if err != nil {
		return err
	}
	s.identityDerivedCutoverID, s.identityDerivedAfter = id, after
	return nil
}

func identityDerivedCandidateQuery(sensor string, priority int, after time.Time) (string, []any) {
	if after.IsZero() {
		return identityDerivedReadyCandidateSQL, []any{sensor, priority}
	}
	// Restrict both bounded index ranges before joining any old fragment body.
	query := strings.ReplaceAll(identityDerivedReadyCandidateSQL, "sensor_id=$1 AND priority=$2", "sensor_id=$1 AND priority=$2 AND accepted_at >= $3")
	return query, []any{sensor, priority, after}
}

func (s *DBStore) runIdentityFreshHealth(ctx context.Context, name string) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 5*time.Second)
		var events int64
		var done bool
		err := s.pg.db.QueryRowContext(work, `SELECT cancelled_events,done FROM identity_derived_cancel_progress WHERE cancel_id=$1`, s.pg.identityDerivedCutoverID).Scan(&events, &done)
		if err == nil {
			state, _ := json.Marshal(map[string]any{
				"last_checked_at": time.Now().UTC(), "last_error": "", "mode": "fresh_fragments_only",
				"accepted_after": s.pg.identityDerivedAfter, "cancel_id": s.pg.identityDerivedCutoverID,
				"historical_state": "cancelled_unprocessed", "historical_cancelled_events": events,
				"historical_cancellation_audit_complete": done, "legacy_polling": "retired",
				"historical_archive": "paused_unprocessed", "archive_mode": "fixed_fresh_boundary",
				"authentication_projection": "sessions_and_endpoint_evidence", "device_profiles": "asynchronous_on_change",
			})
			_, err = s.pg.db.ExecContext(work, `INSERT INTO read_model_runtime_state(name,state) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, name, state)
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "identity fresh health:", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}
