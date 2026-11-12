package discovery

import (
	"context"
	"database/sql"
	"time"
)

// Choose the latest committed state across active source epochs before testing
// whether it is current. An expiry must not resurrect an older current epoch.
const ActiveStreamLatestPredicate = `NOT EXISTS(SELECT 1 FROM stream_discovery_device_state newer
 WHERE newer.device_key=s.device_key AND newer.result_version>s.result_version
 AND EXISTS(SELECT 1 FROM stream_source_cutovers nc WHERE nc.epoch=newer.epoch AND nc.state='active') OFFSET 0)`

const ActiveStreamCurrentPredicate = `s.document->>'current'='true' AND ` + ActiveStreamLatestPredicate

// StreamCurrentRelation is read-only; it requires no copied current table,
// historical body aggregation, cache hydration or background reconciliation.
const StreamCurrentRelation = `(SELECT s.device_key,s.last_seen,s.document
 FROM stream_discovery_device_state s
 WHERE EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.epoch=s.epoch AND c.state='active')
 AND ` + ActiveStreamCurrentPredicate + `) stream_current`

// StreamCurrentFreshness compares journal acceptance and projection completion
// for the last completed segment in each active epoch. The source cursor and
// unprojected journal segments are not stored in PostgreSQL, so even a recent
// completion cannot prove that the projection has caught up with its source.
func (r Repository) StreamCurrentFreshness(ctx context.Context) (map[string]any, error) {
	var accepted, projected sql.NullTime
	var processingLag sql.NullFloat64
	var version sql.NullInt64
	var active, projectedEpochs int64
	err := r.DB.QueryRowContext(ctx, `SELECT min(p.accepted_at),min(p.projected_at),
 max(CASE WHEN p.projected_at IS NOT NULL THEN greatest(extract(epoch from p.projected_at-p.accepted_at),0) END)::double precision,
 max(s.result_version),count(*),count(p.projected_at)
 FROM (SELECT DISTINCT epoch FROM stream_source_cutovers WHERE state='active') c
 LEFT JOIN LATERAL (SELECT accepted_at,projected_at FROM stream_projection_segments
  WHERE epoch=c.epoch ORDER BY projected_at DESC LIMIT 1) p ON true
 LEFT JOIN LATERAL (SELECT result_version FROM stream_discovery_device_state
  WHERE epoch=c.epoch ORDER BY result_version DESC LIMIT 1) s ON true`).Scan(&accepted, &projected, &processingLag, &version, &active, &projectedEpochs)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"source": "stream", "status": "initializing", "result_version": version.Int64,
		"lag_seconds": float64(0), "source_progress_status": "unverified", "archive_status": "unverified",
		"active_epochs": active, "projected_epochs": projectedEpochs}
	if accepted.Valid {
		// This is only the last *projected* input per epoch, never the source
		// cursor or proof that no older journal segment is still pending.
		result["last_projected_input_at"] = accepted.Time
	}
	if processingLag.Valid {
		result["processing_lag_seconds"] = processingLag.Float64
	}
	if projected.Valid {
		result["processed_at"] = projected.Time
		idle := max(0, time.Since(projected.Time).Seconds())
		lag := max(idle, processingLag.Float64)
		result["lag_seconds"] = lag
		result["status"] = "unknown"
		if projectedEpochs < active {
			result["status"] = "initializing"
		} else if lag > (5 * time.Minute).Seconds() {
			result["status"] = "delayed"
		}
	}
	return result, nil
}

// EventBusCurrentFreshness compares each active epoch's copy cursor with its
// maintained state. A zero Kafka consumer lag is not evidence that this copied
// table is current, because the producer and copy worker are independent.
func (r Repository) EventBusCurrentFreshness(ctx context.Context) (map[string]any, error) {
	var updated sql.NullTime
	var version sql.NullInt64
	var active, copiedEpochs int64
	var caughtUp bool
	err := r.DB.QueryRowContext(ctx, `SELECT count(*),count(p.epoch),
 coalesce(bool_and(p.last_result_version>=coalesce(s.result_version,0)),false),
 min(p.updated_at),max(p.last_result_version)
 FROM (SELECT DISTINCT epoch FROM stream_source_cutovers WHERE state='active') c
 LEFT JOIN discovery_current_stream_progress p ON p.epoch=c.epoch
 LEFT JOIN LATERAL (SELECT result_version FROM stream_discovery_device_state
  WHERE epoch=c.epoch ORDER BY result_version DESC LIMIT 1) s ON true`).Scan(&active, &copiedEpochs, &caughtUp, &updated, &version)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"source": "eventbus", "status": "initializing", "lag_seconds": float64(0),
		"result_version": version.Int64, "source_progress_status": "unverified",
		"active_epochs": active, "projected_epochs": copiedEpochs}
	if updated.Valid {
		age := max(0, time.Since(updated.Time).Seconds())
		result["processed_at"] = updated.Time
		result["lag_seconds"] = age
		if copiedEpochs < active || !caughtUp || age > (5*time.Minute).Seconds() {
			result["status"] = "delayed"
		} else {
			result["status"] = "processing"
		}
	}
	return result, nil
}
