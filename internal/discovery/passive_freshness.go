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
