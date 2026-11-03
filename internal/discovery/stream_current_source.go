package discovery

import (
	"context"
	"database/sql"
	"time"
)

// Choose the latest committed state across active source epochs before testing
// whether it is current. An expiry must not resurrect an older current epoch.
const ActiveStreamCurrentPredicate = `s.document->>'current'='true'
 AND NOT EXISTS(SELECT 1 FROM stream_discovery_device_state newer
 WHERE newer.device_key=s.device_key AND newer.result_version>s.result_version
 AND EXISTS(SELECT 1 FROM stream_source_cutovers nc WHERE nc.epoch=newer.epoch AND nc.state='active') OFFSET 0)`

// StreamCurrentRelation is read-only; it requires no copied current table,
// historical body aggregation, cache hydration or background reconciliation.
const StreamCurrentRelation = `(SELECT s.device_key,s.last_seen,s.document
 FROM stream_discovery_device_state s
 WHERE EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.epoch=s.epoch AND c.state='active')
 AND ` + ActiveStreamCurrentPredicate + `) stream_current`

// StreamCurrentFreshness reports the maintained state only. Archive receipts
// and source queue progress belong to their independent processing endpoints.
func (r Repository) StreamCurrentFreshness(ctx context.Context) (map[string]any, error) {
	var updated sql.NullTime
	var version sql.NullInt64
	err := r.DB.QueryRowContext(ctx, `SELECT max(s.updated_at),max(s.result_version)
 FROM (SELECT DISTINCT epoch FROM stream_source_cutovers WHERE state='active') c
 LEFT JOIN LATERAL (SELECT updated_at,result_version FROM stream_discovery_device_state
  WHERE epoch=c.epoch ORDER BY result_version DESC LIMIT 1) s ON true`).Scan(&updated, &version)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"source": "stream", "status": "initializing", "result_version": version.Int64,
		"source_progress_status": "unverified", "archive_status": "unverified"}
	if updated.Valid {
		result["processed_at"] = updated.Time
		result["status"] = "processing"
		if time.Since(updated.Time) > 5*time.Minute {
			result["status"] = "delayed"
		}
	}
	return result, nil
}
