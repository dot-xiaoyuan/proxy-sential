package discovery

import (
	"context"
	"database/sql"
	"time"
)

func (r Repository) streamDiscoveryFreshness(ctx context.Context) (map[string]any, error) {
	var oldest, projected sql.NullTime
	var version sql.NullInt64
	err := r.DB.QueryRowContext(ctx, `SELECT min(pending.accepted_at),max(projected.projected_at),max(state.result_version)
 FROM (SELECT DISTINCT epoch FROM stream_source_cutovers WHERE state='active') c
 LEFT JOIN LATERAL (SELECT accepted_at FROM stream_discovery_receipts WHERE epoch=c.epoch AND archive_state='pending' ORDER BY accepted_at LIMIT 1) pending ON true
 LEFT JOIN LATERAL (SELECT projected_at FROM stream_projection_segments WHERE epoch=c.epoch ORDER BY projected_at DESC LIMIT 1) projected ON true
 LEFT JOIN LATERAL (SELECT result_version FROM stream_discovery_device_state WHERE epoch=c.epoch ORDER BY result_version DESC LIMIT 1) state ON true`).Scan(&oldest, &projected, &version)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"generation": "fresh", "status": "processing", "result_version": version.Int64, "source_progress_status": "unverified", "archive_lag_seconds": float64(0)}
	if !projected.Valid {
		result["status"] = "initializing"
	} else {
		result["processed_at"] = projected.Time
	}
	if oldest.Valid {
		lag := time.Since(oldest.Time).Seconds()
		result["archive_oldest_pending_at"] = oldest.Time
		result["archive_lag_seconds"] = lag
		if lag > 5 {
			result["status"] = "delayed"
		}
	}
	return result, nil
}
