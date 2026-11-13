package discovery

import (
	"context"
	"database/sql"
	"time"
)

// passiveDiscoveryDelayThreshold is how far behind the persisted cursor may run
// before the devices response is labelled delayed. The materializer reads with a
// five minute holdback, so a healthy cursor always sits about five minutes
// behind now; ten minutes means the projection is genuinely behind.
const passiveDiscoveryDelayThreshold = 10 * time.Minute

// PassiveDiscoveryFreshness reports how current the indexed discovery view is.
// The control plane renders the result as a warning banner, so a failed read is
// omitted instead of failing the whole device page.
func (r Repository) PassiveDiscoveryFreshness(ctx context.Context) map[string]any {
	if r.DB == nil {
		return nil
	}
	active, stateErr := r.PassiveDiscoveryBatchActive(ctx)
	if stateErr != nil {
		return map[string]any{"status": "failed", "source": "passive-discovery-batch-v3", "error": "batch read state unavailable"}
	}
	if active {
		fresh, err := r.PassiveDiscoveryBatchFreshness(ctx)
		if err != nil {
			return nil
		}
		return fresh
	}
	probe, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	var cursor, success, updated sql.NullTime
	var lastError sql.NullString
	err := r.DB.QueryRowContext(probe, `SELECT cursor_timestamp,last_success_at,last_error,updated_at FROM passive_discovery_state ORDER BY updated_at DESC LIMIT 1`).Scan(&cursor, &success, &lastError, &updated)
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	result := map[string]any{"status": "ready", "lag_seconds": float64(0), "source": "passive-discovery"}
	if !cursor.Valid {
		result["status"] = "initializing"
	} else {
		lag := now.Sub(cursor.Time).Seconds()
		if lag < 0 {
			lag = 0
		}
		result["lag_seconds"] = lag
		result["cursor_at"] = cursor.Time
		// The oldest unprocessed instant is the cursor itself.
		result["oldest_pending_at"] = cursor.Time
		if lag > passiveDiscoveryDelayThreshold.Seconds() {
			result["status"] = "delayed"
		}
	}
	if success.Valid {
		result["last_success_at"] = success.Time
	}
	if lastError.Valid && lastError.String != "" && updated.Valid && now.Sub(updated.Time) < 2*time.Minute {
		result["status"] = "failed"
		result["error"] = lastError.String
	}
	return result
}

func (r Repository) PassiveDiscoveryBatchActive(ctx context.Context) (bool, error) {
	var active bool
	err := r.DB.QueryRowContext(ctx, `SELECT COALESCE((state->>'active')::boolean,false) FROM read_model_runtime_state WHERE name='passive-discovery-batch-v3'`).Scan(&active)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return active, err
}

// PassiveDiscoveryBatchFreshness uses the oldest unfinished source batch,
// including retry gaps. A completed newer batch cannot make a stale gap look
// current; classification and archive progress are reported separately.
func (r Repository) PassiveDiscoveryBatchFreshness(ctx context.Context) (map[string]any, error) {
	probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var oldest, ingested, processed, archived, archiveOldest sql.NullTime
	var failure sql.NullString
	var pending, archivePending int64
	err := r.DB.QueryRowContext(probe, `SELECT
 (SELECT min(first_ingested_at) FROM passive_discovery_batch_progress WHERE completed_at IS NULL AND first_ingested_at IS NOT NULL),
 (SELECT max(first_ingested_at) FROM passive_discovery_batch_progress),
 (SELECT max(completed_at) FROM passive_discovery_batch_progress),
 (SELECT max(archive_verified_at) FROM passive_discovery_batch_progress),
 (SELECT min(first_ingested_at) FROM passive_discovery_batch_progress WHERE archive_verified_at IS NULL AND first_ingested_at IS NOT NULL AND selected_count>0),
 (SELECT last_error FROM passive_discovery_batch_progress WHERE completed_at IS NULL AND last_error<>'' ORDER BY first_ingested_at,batch_id LIMIT 1),
 (SELECT count(*) FROM passive_discovery_batch_progress WHERE completed_at IS NULL AND first_ingested_at IS NOT NULL),
 (SELECT count(*) FROM passive_discovery_batch_progress WHERE archive_verified_at IS NULL AND first_ingested_at IS NOT NULL AND selected_count>0)`).Scan(&oldest, &ingested, &processed, &archived, &archiveOldest, &failure, &pending, &archivePending)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"status": "ready", "source": "passive-discovery-batch-v3", "pending_batches": pending, "archive_pending_batches": archivePending, "lag_seconds": float64(0)}
	if !processed.Valid {
		result["status"] = "initializing"
	}
	if oldest.Valid {
		lag := time.Since(oldest.Time).Seconds()
		if lag < 0 {
			lag = 0
		}
		result["oldest_pending_at"] = oldest.Time
		result["lag_seconds"] = lag
		if lag > passiveDiscoveryDelayThreshold.Seconds() {
			result["status"] = "delayed"
		} else {
			result["status"] = "processing"
		}
	}
	if ingested.Valid {
		result["ingested_at"] = ingested.Time
	}
	if processed.Valid {
		result["processed_at"] = processed.Time
		result["last_success_at"] = processed.Time
	}
	if archived.Valid {
		result["archive_verified_at"] = archived.Time
	}
	if archiveOldest.Valid {
		result["archive_oldest_pending_at"] = archiveOldest.Time
		result["archive_lag_seconds"] = max(0, time.Since(archiveOldest.Time).Seconds())
	}
	if failure.Valid && failure.String != "" {
		result["status"] = "failed"
		result["error"] = failure.String
	}
	return result, nil
}
