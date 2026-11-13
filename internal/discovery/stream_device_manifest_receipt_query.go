package discovery

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// A legacy stream- key keeps its original identity and body hash. Only keys
// with an explicit segment locator may use the device-signals manifest when
// their per-event receipt is absent.
var deviceManifestReceiptColumns = []string{"event_key", "content_sha256", "first_accepted_at", "accepted_month", "receipt_segment_id", "receipt_ordinal", "epoch", "source_kind", "source_path", "archive_receipt_mode", "event_count", "accepted_at", "projected_at", "lanes_finalized_at", "source_file_id", "source_start_offset", "source_end_offset", "source_generation", "archive_month", "body_layout", "key_scheme", "result_count", "result"}

func (r Repository) streamDeviceManifestReceipts(ctx context.Context, epoch, scope string, keys []string) (map[string]map[string]any, error) {
	out := make(map[string]map[string]any, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT k.event_key,k.content_sha256,k.first_accepted_at,k.accepted_month,k.receipt_segment_id,k.receipt_ordinal,
 s.epoch,s.source_kind,s.source_path,s.archive_receipt_mode,s.event_count,s.accepted_at,s.projected_at,s.lanes_finalized_at,
 s.source_file_id,s.source_start_offset,s.source_end_offset,s.source_generation,
 m.archive_month,m.body_layout,m.key_scheme,jsonb_array_length(m.results),m.results->>k.receipt_ordinal
 FROM jsonb_array_elements_text($3::jsonb) AS v(value)
 JOIN LATERAL (SELECT event_key,content_sha256,first_accepted_at,accepted_month,receipt_segment_id,receipt_ordinal
  FROM stream_discovery_event_keys k WHERE k.epoch=$1 AND k.scope_id=$2 AND k.event_key=v.value OFFSET 0) k ON true
 LEFT JOIN stream_projection_segments s ON s.segment_id=k.receipt_segment_id
 LEFT JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=s.segment_id`, epoch, scope, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, hash string
		var accepted, acceptedMonth time.Time
		var locator, markerEpoch, source, path, mode, fileID, month, layout, scheme sql.NullString
		var ordinal, eventCount, start, end, generation, resultCount sql.NullInt64
		var markerAccepted, projected, finalized sql.NullTime
		var result sql.NullString
		if err := rows.Scan(&key, &hash, &accepted, &acceptedMonth, &locator, &ordinal,
			&markerEpoch, &source, &path, &mode, &eventCount, &markerAccepted, &projected, &finalized,
			&fileID, &start, &end, &generation, &month, &layout, &scheme, &resultCount, &result); err != nil {
			return nil, err
		}
		if !locator.Valid || locator.String == "" || !ordinal.Valid {
			return nil, fmt.Errorf("device signal key %s has no receipt or manifest locator: %w", key, streamlog.ErrUnconfirmed)
		}
		decoded, hashErr := hex.DecodeString(hash)
		if !markerEpoch.Valid || markerEpoch.String != epoch || !source.Valid || source.String != "device-signals" ||
			hashErr != nil || len(decoded) != 32 ||
			!path.Valid || path.String == "" || !mode.Valid || mode.String != "manifest" ||
			!eventCount.Valid || eventCount.Int64 < 1 || eventCount.Int64 > streamlog.MaxPassiveSegmentEvents ||
			!markerAccepted.Valid || !streamAcceptedAtMatches(markerAccepted.Time, accepted) || !projected.Valid ||
			!fileID.Valid || fileID.String == "" || !start.Valid || start.Int64 < 0 || !end.Valid || end.Int64 <= start.Int64 ||
			!generation.Valid || generation.Int64 < 0 ||
			streamlog.SourceSegmentID(streamlog.Segment{Epoch: epoch, Source: source.String, SourcePath: path.String, FileID: fileID.String, StartOffset: start.Int64, EndOffset: end.Int64, SourceGeneration: uint64(generation.Int64)}) != locator.String ||
			!month.Valid || month.String != acceptedMonth.UTC().Format("200601") ||
			!layout.Valid || (layout.String != "" && layout.String != "v2") || !scheme.Valid || scheme.String != "device-signals" ||
			!resultCount.Valid || resultCount.Int64 != eventCount.Int64 || ordinal.Int64 < 0 || ordinal.Int64 >= eventCount.Int64 ||
			!result.Valid || result.String == "" {
			return nil, fmt.Errorf("device signal key %s has a conflicting manifest proof: %w", key, streamlog.ErrContentConflict)
		}
		fields := map[string]string{"epoch": epoch, "class": "evidence", "month": month.String, "scope": scope, "key": key, "sha256": hash}
		if layout.String != "" {
			fields["body_layout"] = layout.String
		}
		ref, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		archive := "pending"
		if finalized.Valid {
			archive = "confirmed"
		}
		out[key] = map[string]any{"generation": "fresh", "epoch": epoch, "scope_id": scope, "event_key": key,
			"content_sha256": hash, "first_accepted_at": accepted, "projected_at": projected.Time,
			"result": result.String, "archive_state": archive, "body_ref": json.RawMessage(ref)}
	}
	return out, rows.Err()
}
