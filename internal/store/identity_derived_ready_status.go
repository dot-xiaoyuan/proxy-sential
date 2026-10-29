package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// The compact snapshot describes only the ready-key index. It cannot count
// unregistered, not-yet-eligible, or failed fragments, and therefore never
// represents an empty index as completion of the entire identity pipeline.
type identityDerivedReadyStatus struct {
	State                    string    `json:"state"`
	Scope                    string    `json:"scope"`
	PendingKeyScanComplete   bool      `json:"pending_key_scan_complete"`
	FreshIndexKeysPresent    bool      `json:"fresh_index_keys_present"`
	ExistingIndexKeysPresent bool      `json:"existing_index_keys_present"`
	IndexErrorKeysPresent    bool      `json:"index_error_keys_present"`
	SampledAt                time.Time `json:"sampled_at"`
	FreshStartID             string    `json:"fresh_start_id,omitempty"`
	AcceptedAfter            string    `json:"accepted_after,omitempty"`
	HistoricalIndexRetired   bool      `json:"historical_index_retired,omitempty"`
}

const persistIdentityDerivedReadyStatusSQL = `INSERT INTO read_model_runtime_state(name,state) VALUES($1,$2)
 ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()
 WHERE COALESCE((read_model_runtime_state.state->>'sampled_at')::timestamptz,'-infinity'::timestamptz)<=(EXCLUDED.state->>'sampled_at')::timestamptz`

func (s *PostgresStore) publishIdentityDerivedReadyStatus(ctx context.Context) error {
	var done, fresh, older, hasError bool
	var sampled time.Time
	query := `SELECT s.done,EXISTS(SELECT 1 FROM identity_derived_ready q WHERE q.sensor_id=$1 AND q.priority=0),EXISTS(SELECT 1 FROM identity_derived_ready q WHERE q.sensor_id=$1 AND q.priority=1),EXISTS(SELECT 1 FROM identity_derived_ready q WHERE q.sensor_id=$1 AND q.last_error<>''),clock_timestamp() FROM identity_derived_ready_scan s WHERE s.id=true`
	args := []any{s.sensorID}
	if !s.identityDerivedAfter.IsZero() {
		query = strings.ReplaceAll(query, "q.sensor_id=$1", "q.sensor_id=$1 AND q.accepted_at >= $2")
		args = append(args, s.identityDerivedAfter)
	}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&done, &fresh, &older, &hasError, &sampled)
	if err != nil {
		return err
	}
	state := "indexing"
	if done && hasError {
		state = "index_errors"
	} else if done && (fresh || older) {
		state = "index_keys_present"
	} else if done {
		state = "ready_index_empty"
	}
	status := identityDerivedReadyStatus{State: state, Scope: "ready_index_only", PendingKeyScanComplete: done, FreshIndexKeysPresent: fresh, ExistingIndexKeysPresent: older, IndexErrorKeysPresent: hasError, SampledAt: sampled.UTC()}
	if !s.identityDerivedAfter.IsZero() {
		status.Scope, status.State = "fresh_index_only", "fresh_index_empty"
		if fresh || older {
			status.State = "fresh_index_keys_present"
		}
		if hasError {
			status.State = "fresh_index_errors"
		}
		status.FreshStartID = s.identityDerivedCutoverID
		status.AcceptedAfter = s.identityDerivedAfter.UTC().Format(time.RFC3339Nano)
		status.HistoricalIndexRetired = true
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, persistIdentityDerivedReadyStatusSQL, "identity-derived-ready:"+s.sensorID, raw)
	return err
}
