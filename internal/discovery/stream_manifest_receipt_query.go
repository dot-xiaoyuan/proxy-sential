package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// This path is used only when an exact event receipt is absent. Shadow
// manifests never replace their authoritative receipt; a later writer marks
// deliberately omitted receipts with archive_receipt_mode='manifest'.
func (r Repository) streamManifestReceipts(ctx context.Context, epoch, scope string, keys []string) (map[string]map[string]any, error) {
	out := make(map[string]map[string]any, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT k.event_key,k.content_sha256,k.first_accepted_at,k.accepted_month,k.receipt_segment_id,k.receipt_ordinal,
 s.epoch,s.source_kind,s.archive_receipt_mode,s.event_count,s.projected_at,s.lanes_finalized_at,
 s.source_file_id,s.source_start_offset,s.source_end_offset,m.archive_month,m.body_layout,
 jsonb_array_length(m.results),m.results->>k.receipt_ordinal
 FROM jsonb_array_elements_text($3::jsonb) AS v(value)
	 JOIN LATERAL (SELECT k.event_key,k.content_sha256,k.first_accepted_at,k.accepted_month,k.receipt_segment_id,k.receipt_ordinal
  FROM stream_discovery_event_keys_compact k
  WHERE k.key_hash=sentinel_stream_discovery_key_hash($1,$2,v.value)
   AND k.epoch=$1 AND k.scope_id=$2 AND k.event_key=v.value OFFSET 0) k ON true
 LEFT JOIN stream_projection_segments s ON s.segment_id=k.receipt_segment_id
 LEFT JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=s.segment_id`, epoch, scope, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, hash string
		var accepted, acceptedMonth time.Time
		var locator, segmentEpoch, source, mode, fileID, archiveMonth, bodyLayout sql.NullString
		var ordinal, eventCount, sourceStart, sourceEnd, resultCount sql.NullInt64
		var projected, finalized sql.NullTime
		var result sql.NullString
		if err := rows.Scan(&key, &hash, &accepted, &acceptedMonth, &locator, &ordinal,
			&segmentEpoch, &source, &mode, &eventCount, &projected, &finalized,
			&fileID, &sourceStart, &sourceEnd, &archiveMonth, &bodyLayout, &resultCount, &result); err != nil {
			return nil, err
		}
		if !locator.Valid || locator.String == "" || !ordinal.Valid {
			return nil, fmt.Errorf("stream compact key %s lacks receipt and segment locator: %w", key, streamlog.ErrUnconfirmed)
		}
		if mode.Valid && mode.String != "manifest" {
			return nil, fmt.Errorf("stream compact key %s lost its event receipt in %s mode: %w", key, mode.String, streamlog.ErrUnconfirmed)
		}
		if !segmentEpoch.Valid || segmentEpoch.String != epoch || !source.Valid || source.String != "passive-discovery" ||
			!mode.Valid || !eventCount.Valid || !projected.Valid || !fileID.Valid || fileID.String == "" || !sourceStart.Valid || !sourceEnd.Valid ||
			sourceEnd.Int64 <= sourceStart.Int64 || !archiveMonth.Valid || archiveMonth.String != acceptedMonth.Format("200601") ||
			!bodyLayout.Valid || (bodyLayout.String != "" && bodyLayout.String != "v2") || !resultCount.Valid {
			return nil, fmt.Errorf("stream compact key %s has an incomplete receipt manifest: %w", key, streamlog.ErrContentConflict)
		}
		if resultCount.Int64 != eventCount.Int64 || ordinal.Int64 < 0 || ordinal.Int64 >= resultCount.Int64 ||
			!result.Valid || result.String == "" {
			return nil, fmt.Errorf("stream compact key %s has a conflicting receipt result: %w", key, streamlog.ErrContentConflict)
		}
		fields := map[string]string{"epoch": epoch, "class": "evidence", "month": archiveMonth.String, "scope": scope, "key": key, "sha256": hash}
		if bodyLayout.String != "" {
			fields["body_layout"] = bodyLayout.String
		}
		bodyRef, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		archive := "pending"
		if finalized.Valid {
			archive = "confirmed"
		}
		out[key] = map[string]any{"generation": "fresh", "epoch": epoch, "scope_id": scope, "event_key": key,
			"content_sha256": hash, "first_accepted_at": accepted, "projected_at": projected.Time,
			"result": result.String, "archive_state": archive, "body_ref": json.RawMessage(bodyRef)}
	}
	return out, rows.Err()
}

func (r Repository) missingLegacyReceipt(ctx context.Context, epoch, scope string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	var key string
	err = r.DB.QueryRowContext(ctx, `SELECT k.event_key FROM jsonb_array_elements_text($3::jsonb) AS v(value)
 JOIN LATERAL (SELECT event_key FROM stream_discovery_event_keys k
  WHERE k.epoch=$1 AND k.scope_id=$2 AND k.event_key=v.value OFFSET 0) k ON true LIMIT 1`, epoch, scope, raw).Scan(&key)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("stream event key %s has no receipt: %w", key, streamlog.ErrUnconfirmed)
}
