package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// passiveStreamCaptureHealth is intentionally optional on /readyz. A backlog
// pause is an operational fault, but making the API restart on that condition
// would make the discovery worker repeat its expensive journal recovery.
// Capture and projection watermarks are distinct: neither proves that every
// source segment has been projected, because journal pending state is local.
func passiveStreamCaptureHealth(ctx context.Context, db *sql.DB, sensor string) componentHealth {
	var enabled int64
	var captured sql.NullTime
	var captureError sql.NullString
	err := db.QueryRowContext(ctx, `SELECT count(*),min(updated_at),min(nullif(error,''))
 FROM discovery_protocol_runtime
 WHERE sensor_id=$1 AND owner='discovery-worker' AND enabled`, sensor).Scan(&enabled, &captured, &captureError)
	if err != nil {
		return componentHealth{Status: "unavailable", Error: "capture_watermark_read_failed"}
	}
	now := time.Now()
	item := classifyPassiveStreamCapture(enabled, captured, captureError, now)
	var epoch string
	var acceptedAt, projectedAt time.Time
	err = db.QueryRowContext(ctx, `SELECT c.epoch,p.accepted_at,p.projected_at
 FROM stream_source_cutovers c
 JOIN LATERAL (SELECT accepted_at,projected_at FROM stream_projection_segments
  WHERE epoch=c.epoch ORDER BY projected_at DESC LIMIT 1) p ON true
 WHERE c.sensor_id=$1 AND c.source_kind='passive-discovery' AND c.state='active'
 ORDER BY c.cutover_at DESC LIMIT 1`, sensor).Scan(&epoch, &acceptedAt, &projectedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if item.Status == "ready" {
			item.Status = "initializing"
		}
		item.Error = strings.TrimSpace(item.Error + " projection_watermark_absent")
		return item
	}
	if err != nil {
		if item.Status == "ready" {
			item.Status = "unavailable"
		}
		item.Error = strings.TrimSpace(item.Error + " projection_watermark_read_failed")
		return item
	}
	item.SourceEpoch = epoch
	item.LastProjectedInputAt = acceptedAt.UTC().Format(time.RFC3339Nano)
	item.ProcessedAt = projectedAt.UTC().Format(time.RFC3339Nano)
	lag := max(0, projectedAt.Sub(acceptedAt).Seconds())
	item.ProcessingLagSeconds = &lag
	if lag > (5 * time.Minute).Seconds() {
		if item.Status == "ready" {
			item.Status = "delayed"
		}
		item.Error = strings.TrimSpace(item.Error + " " + fmt.Sprintf("last_completed_processing_lag=%s", time.Duration(lag*float64(time.Second)).Round(time.Second)))
	}
	// A quiet source may have no new segment to project. Without the local
	// journal cursor, an old completion cannot prove either a current backlog
	// or that the projection is caught up.
	if now.Sub(projectedAt) > 5*time.Minute {
		if item.Status == "ready" {
			item.Status = "unknown"
		}
		item.Error = strings.TrimSpace(item.Error + " projection_progress_unverified")
	}
	return item
}

func classifyPassiveStreamCapture(enabled int64, captured sql.NullTime, captureError sql.NullString, now time.Time) componentHealth {
	item := componentHealth{Status: "ready", SourceProgressStatus: "unverified"}
	if enabled == 0 {
		item.Status, item.Error = "initializing", "passive_capture_not_configured"
		return item
	}
	if !captured.Valid {
		item.Status, item.Error = "stale", "capture_watermark_absent"
		return item
	}
	item.UpdatedAt = captured.Time.UTC().Format(time.RFC3339Nano)
	if captured.Time.After(now.Add(5 * time.Second)) {
		item.Status, item.Error = "failed", "capture_watermark_in_future"
		return item
	}
	age := now.Sub(captured.Time)
	if age > 5*time.Minute {
		item.Status, item.Error = "stale", fmt.Sprintf("capture_heartbeat_stale age=%s", age.Round(time.Second))
		return item
	}
	if age > 15*time.Second {
		item.Status, item.Error = "delayed", fmt.Sprintf("capture_heartbeat_stale age=%s", age.Round(time.Second))
		return item
	}
	if captureError.Valid && strings.TrimSpace(captureError.String) != "" {
		item.Status = "failed"
		item.Error = "capture_runtime_error"
		if captureError.String == "capture_heartbeat_stale" {
			item.Status, item.Error = "delayed", "capture_heartbeat_stale"
		}
	}
	return item
}
