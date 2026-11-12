package discovery

import (
	"context"
	"database/sql"
	"time"
)

// HardwareFreshness distinguishes an empty result from pending/retrying work.
// Its timeout cannot block a device list behind a failed projection worker.
func (r Repository) HardwareFreshness(ctx context.Context) map[string]any {
	if !r.HardwareV2 || r.DB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	var pending, failed int64
	var oldest sql.NullTime
	var lastError string
	err := r.DB.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE last_error<>''),min(first_enqueued_at),coalesce(max(last_error),'') FROM passive_hardware_dirty WHERE ($1='' OR sensor_id=$1)`, r.ClaimSensor).Scan(&pending, &failed, &oldest, &lastError)
	if err != nil {
		return map[string]any{"status": "failed", "error": "hardware projection progress query failed"}
	}
	result := map[string]any{"status": "ready", "pending_identities": pending, "failed_identities": failed, "classification_version": "passive-hardware/v2"}
	if pending > 0 {
		result["status"] = "processing"
	}
	if failed > 0 {
		result["status"] = "failed"
		result["error"] = lastError
	}
	if oldest.Valid {
		result["oldest_pending_at"] = oldest.Time
	}
	var complete bool
	var count, missing, changed int64
	var available, last sql.NullTime
	var runtimeError string
	err = r.DB.QueryRowContext(ctx, `SELECT backfill_complete,backfill_rows,backfill_missing_refs,backfill_changed_rows,available_from,last_success_at,last_error FROM passive_hardware_runtime WHERE ($1='' OR sensor_id=$1) ORDER BY updated_at DESC LIMIT 1`, r.ClaimSensor).Scan(&complete, &count, &missing, &changed, &available, &last, &runtimeError)
	if err == nil {
		result["backfill_complete"] = complete
		result["backfill_rows"] = count
		result["missing_source_refs"] = missing
		result["changed_after_backfill_start"] = changed
		result["coverage"] = "retained_latest_only"
		if count == 0 && !complete {
			result["coverage"] = "live_input_only"
		}
		if runtimeError != "" {
			result["status"] = "failed"
			result["error"] = runtimeError
		}
		if available.Valid {
			result["available_from"] = available.Time
		}
		if last.Valid {
			result["last_success_at"] = last.Time
		}
	} else if err == sql.ErrNoRows {
		result["backfill_complete"] = false
		result["coverage"] = "live_input_only"
	} else {
		result["status"] = "failed"
		result["error"] = "hardware projection runtime query failed"
	}
	return result
}
