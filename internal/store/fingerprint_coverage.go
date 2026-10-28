package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Coverage is refreshed by a background worker from the recognition read model.
// Counts describe current rule/endpoint relationships, not packet or scan counts.
func (s *DBStore) runFingerprintCoverage(ctx context.Context) {
	var retryDelay time.Duration
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := s.flushFingerprintMatchCounts(work)
		if err == nil {
			err = s.refreshFingerprintCoverage(work)
		}
		if err == nil {
			err = s.refreshFreshRecognitionCoverage(work)
		}
		cancel()
		retryDelay = nextFingerprintCoverageDelay(retryDelay, err == nil)
		if err != nil && ctx.Err() == nil {
			fmt.Printf("fingerprint coverage update failed: %v; retry in %s\n", err, retryDelay)
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// The 24-hour aggregation can spill to disk under resource pressure. Avoid
// retrying it every minute after repeated failures; the stored snapshot is
// explicitly marked stale by the read path until a refresh succeeds.
func nextFingerprintCoverageDelay(previous time.Duration, success bool) time.Duration {
	if success || previous < time.Minute {
		return time.Minute
	}
	if previous >= 5*time.Minute/2 {
		return 5 * time.Minute
	}
	return 2 * previous
}
func (s *DBStore) FingerprintSourceCoverage(ctx context.Context) (map[string]any, error) {
	var raw []byte
	err := s.pg.db.QueryRowContext(ctx, `SELECT state FROM read_model_runtime_state WHERE name='fingerprint-source-coverage'`).Scan(&raw)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	out := map[string]any{"status": "pending", "items": []any{}, "window": "24h"}
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	if stamp, ok := out["as_of"].(string); ok {
		if at, e := time.Parse(time.RFC3339Nano, stamp); e == nil && time.Since(at) > 3*time.Minute {
			out["status"] = "stale"
		}
	}
	var rebuild []byte
	if e := s.pg.db.QueryRowContext(ctx, `SELECT state FROM read_model_runtime_state WHERE name='fingerprint-rebuild'`).Scan(&rebuild); e == nil {
		var state map[string]any
		if json.Unmarshal(rebuild, &state) == nil {
			delete(state, "field_versions")
			delete(state, "cursor")
			out["rebuild"] = state
		}
	}
	if err = s.attachFingerprintMatchCounts(ctx, out); err != nil {
		return nil, err
	}
	var fresh []byte
	if e := s.pg.db.QueryRowContext(ctx, `SELECT state FROM read_model_runtime_state WHERE name='recognition-fresh-coverage'`).Scan(&fresh); e == nil {
		var state map[string]any
		if e = json.Unmarshal(fresh, &state); e != nil {
			return nil, e
		}
		if stamp, ok := state["as_of"].(string); ok {
			if at, e := time.Parse(time.RFC3339Nano, stamp); e == nil && time.Since(at) > 3*time.Minute {
				state["status"] = "stale"
			}
		}
		out["fresh"] = state
	} else if e != sql.ErrNoRows {
		return nil, e
	}
	return out, nil
}

func (s *DBStore) refreshFingerprintCoverage(ctx context.Context) error {
	_, err := s.pg.db.ExecContext(ctx, `WITH matches AS (
 SELECT endpoint_id,conflict,(NOT (CASE WHEN jsonb_array_length(COALESCE(summary->'conflict_dimensions','[]'::jsonb))>0 THEN summary->'conflict_dimensions' ? 'device_type' ELSE conflict END) AND COALESCE((summary->>'device_type_confidence')::double precision,0)>=0.8 AND role=m->>'role' AND m->>'strength'='self_report') confirmed,m->>'source_id' source_id,m->>'rule_id' rule_id
 FROM endpoint_recognition_summary CROSS JOIN LATERAL jsonb_array_elements(COALESCE(summary->'source_matches','[]'::jsonb)) m
 WHERE last_seen>now()-interval '24 hours'
 ), counts AS (SELECT source_id,count(*) match_count,count(DISTINCT endpoint_id) endpoint_count,count(DISTINCT endpoint_id) FILTER(WHERE conflict) conflict_count,count(DISTINCT endpoint_id) FILTER(WHERE confirmed) confirmed_count FROM matches GROUP BY source_id),
 overlap_devices AS (SELECT endpoint_id FROM matches GROUP BY endpoint_id HAVING count(DISTINCT source_id)>1)
 INSERT INTO read_model_runtime_state(name,state,updated_at)
 SELECT 'fingerprint-source-coverage',jsonb_build_object('status','ready','as_of',now(),'window','24h','count_semantics','current_rule_endpoint_relationships','matched_endpoints',(SELECT count(DISTINCT endpoint_id) FROM matches),'conflict_endpoints',(SELECT count(DISTINCT endpoint_id) FROM matches WHERE conflict),'overlap_endpoints',(SELECT count(*) FROM overlap_devices),'items',COALESCE((SELECT jsonb_agg(to_jsonb(counts) ORDER BY source_id) FROM counts),'[]'::jsonb)),now()
 ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=EXCLUDED.updated_at`)
	return err
}
