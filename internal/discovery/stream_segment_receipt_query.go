package discovery

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// streamSegmentReceipts looks up only the requested segment IDs. It remains
// available when segment-key producers are off, so a compatible rollback
// release can finish segments accepted before the switch was disabled.
func (r Repository) streamSegmentReceipts(ctx context.Context, epoch, scope string, keys []string) (map[string]map[string]any, error) {
	return r.streamSegmentReceiptsWithChecks(ctx, epoch, scope, keys, true)
}

// The archive lane already holds the immutable journal segment. For stream4
// it verifies the marker and whole hash vector without 1,000 random probes
// into old per-event ledgers. Public reads and case capture still check any
// contradictory auxiliary rows before returning an exact receipt.
func (r Repository) streamSegmentReceiptsWithoutAuxiliaryChecks(ctx context.Context, epoch, scope string, keys []string) (map[string]map[string]any, error) {
	return r.streamSegmentReceiptsWithChecks(ctx, epoch, scope, keys, false)
}

func (r Repository) streamSegmentReceiptsWithChecks(ctx context.Context, epoch, scope string, keys []string, auxiliaryChecks bool) (map[string]map[string]any, error) {
	out := make(map[string]map[string]any, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	requested := make(map[string]map[int]string, len(keys))
	schemes := make(map[string]string, len(keys))
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		id, ordinal, ok := ParsePassiveStream3Key(epoch, key)
		scheme := "stream3"
		if !ok {
			id, ordinal, ok = ParseDeviceStream4Key(epoch, key)
			scheme = "stream4"
		}
		if !ok {
			return nil, fmt.Errorf("invalid segment-located stream key")
		}
		if requested[id] == nil {
			requested[id] = make(map[int]string)
			schemes[id] = scheme
			ids = append(ids, id)
		}
		if schemes[id] != scheme || requested[id][ordinal] != "" && requested[id][ordinal] != key {
			return nil, fmt.Errorf("conflicting segment-located stream key: %w", streamlog.ErrContentConflict)
		}
		requested[id][ordinal] = key
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT s.segment_id,s.epoch,s.source_kind,s.source_path,s.archive_receipt_mode,
	 s.passive_key_scheme,s.source_generation,s.event_count,s.accepted_at,s.projected_at,s.lanes_finalized_at,
 s.source_file_id,s.source_start_offset,s.source_end_offset,
 m.archive_month,m.body_layout,m.key_scheme,m.scope_id,m.content_hashes,m.results
 FROM jsonb_array_elements_text($1::jsonb) AS v(segment_id)
 JOIN stream_projection_segments s ON s.segment_id=v.segment_id
 LEFT JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=s.segment_id`, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, markerEpoch, source, path, mode, markerScheme string
		var sourceGeneration int64
		var eventCount int
		var accepted, projected time.Time
		var finalized sql.NullTime
		var fileID, month, layout, scheme, storedScope sql.NullString
		var start, end sql.NullInt64
		var hashes, resultsRaw []byte
		if err := rows.Scan(&id, &markerEpoch, &source, &path, &mode, &markerScheme,
			&sourceGeneration, &eventCount, &accepted, &projected, &finalized, &fileID, &start, &end,
			&month, &layout, &scheme, &storedScope, &hashes, &resultsRaw); err != nil {
			return nil, err
		}
		if markerEpoch != epoch {
			return nil, fmt.Errorf("stream segment %s epoch conflicts with key: %w", id, streamlog.ErrContentConflict)
		}
		wantedScheme := schemes[id]
		if markerScheme != wantedScheme {
			return nil, fmt.Errorf("stream segment %s has conflicting key scheme: %w", id, streamlog.ErrContentConflict)
		}
		if !scheme.Valid {
			return nil, fmt.Errorf("stream segment %s lacks receipt manifest: %w", id, streamlog.ErrUnconfirmed)
		}
		if scheme.String != wantedScheme {
			return nil, fmt.Errorf("stream segment %s receipt scheme conflicts with its marker: %w", id, streamlog.ErrContentConflict)
		}
		wantedSource := "passive-discovery"
		if wantedScheme == "stream4" {
			wantedSource = "device-signals"
		}
		if source != wantedSource || path == "" || mode != "manifest" || wantedScheme == "stream4" && eventCount > streamlog.MaxSegmentEvents ||
			sourceGeneration < 0 || eventCount < 1 || eventCount > streamlog.MaxPassiveSegmentEvents || accepted.IsZero() || projected.IsZero() ||
			!fileID.Valid || fileID.String == "" || !start.Valid || start.Int64 < 0 || !end.Valid || end.Int64 <= start.Int64 ||
			!month.Valid || month.String != accepted.UTC().Format("200601") || !layout.Valid || (layout.String != "" && layout.String != "v2") ||
			!storedScope.Valid || storedScope.String == "" || len(hashes) != eventCount*32 {
			return nil, fmt.Errorf("stream segment %s has conflicting receipt metadata: %w", id, streamlog.ErrContentConflict)
		}
		if streamlog.SourceSegmentID(streamlog.Segment{Epoch: markerEpoch, Source: source, SourcePath: path,
			FileID: fileID.String, StartOffset: start.Int64, EndOffset: end.Int64, SourceGeneration: uint64(sourceGeneration)}) != id {
			return nil, fmt.Errorf("stream segment %s ID conflicts with source position: %w", id, streamlog.ErrContentConflict)
		}
		if storedScope.String != scope {
			continue
		}
		var results []json.RawMessage
		if err := json.Unmarshal(resultsRaw, &results); err != nil || len(results) != eventCount {
			return nil, fmt.Errorf("stream segment %s has conflicting receipt results: %w", id, streamlog.ErrContentConflict)
		}
		for _, value := range results {
			var result string
			if err := json.Unmarshal(value, &result); err != nil || result == "" {
				return nil, fmt.Errorf("stream segment %s has missing receipt result: %w", id, streamlog.ErrContentConflict)
			}
		}
		for ordinal, key := range requested[id] {
			if ordinal >= eventCount {
				return nil, fmt.Errorf("stream segment %s receipt ordinal out of range: %w", id, streamlog.ErrContentConflict)
			}
			var result string
			if err := json.Unmarshal(results[ordinal], &result); err != nil || result == "" {
				return nil, fmt.Errorf("stream segment %s has missing receipt result: %w", id, streamlog.ErrContentConflict)
			}
			hash := hex.EncodeToString(hashes[ordinal*32 : (ordinal+1)*32])
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
				"content_sha256": hash, "first_accepted_at": accepted, "projected_at": projected,
				"result": result, "archive_state": archive, "body_ref": json.RawMessage(ref)}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if auxiliaryChecks {
		if err := r.verifyStream3Diagnostics(ctx, epoch, scope, out); err != nil {
			return nil, err
		}
		stream4Keys := make([]string, 0)
		for key := range out {
			if _, _, ok := ParseDeviceStream4Key(epoch, key); ok {
				stream4Keys = append(stream4Keys, key)
			}
		}
		if err := r.verifyStream4KeyConflicts(ctx, epoch, scope, stream4Keys); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// A stream4 locator must never borrow a legacy/compact key row. Such a row
// would provide a second potentially contradictory identity for the event.
func (r Repository) verifyStream4KeyConflicts(ctx context.Context, epoch, scope string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	var conflict bool
	err = r.DB.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM jsonb_array_elements_text($3::jsonb) AS v(event_key)
 JOIN stream_discovery_event_keys k ON k.epoch=$1 AND k.scope_id=$2 AND k.event_key=v.event_key
 UNION ALL
 SELECT 1 FROM jsonb_array_elements_text($3::jsonb) AS v(event_key)
 JOIN stream_discovery_event_keys_compact k
  ON k.key_hash=sentinel_stream_discovery_key_hash($1,$2,v.event_key)
  AND k.epoch=$1 AND k.scope_id=$2 AND k.event_key=v.event_key)`, epoch, scope, raw).Scan(&conflict)
	if err != nil {
		return err
	}
	if conflict {
		return streamlog.ErrContentConflict
	}
	return nil
}

// A sampled recognition receipt is not a substitute for the segment proof,
// but an explicit failure or conflicting sampled row cannot be ignored.
func (r Repository) verifyStream3Diagnostics(ctx context.Context, epoch, scope string, receipts map[string]map[string]any) error {
	if len(receipts) == 0 {
		return nil
	}
	type lookup struct {
		Key   string `json:"event_key"`
		Month string `json:"archive_month"`
	}
	keys := make([]string, 0, len(receipts))
	for key := range receipts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	input := make([]lookup, 0, len(keys))
	for _, key := range keys {
		accepted := receipts[key]["first_accepted_at"].(time.Time)
		input = append(input, lookup{Key: key, Month: accepted.UTC().Format("200601")})
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT r.event_key,r.content_sha256,r.accepted_at,r.result,r.body_ref,r.archive_state,r.archive_segment_id
 FROM jsonb_to_recordset($3::jsonb) AS v(event_key text,archive_month text)
 JOIN stream_discovery_receipts r ON r.accepted_month=to_date(v.archive_month,'YYYYMM')
  AND r.epoch=$1 AND r.scope_id=$2 AND r.event_key=v.event_key`, epoch, scope, raw)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, hash, result, state string
		var accepted time.Time
		var rawRef []byte
		var segmentID sql.NullString
		if err := rows.Scan(&key, &hash, &accepted, &result, &rawRef, &state, &segmentID); err != nil {
			return err
		}
		expected, found := receipts[key]
		id, _, valid := ParsePassiveStream3Key(epoch, key)
		if !valid {
			id, _, valid = ParseDeviceStream4Key(epoch, key)
		}
		if !found || !valid || !segmentID.Valid || segmentID.String != id ||
			hash != expected["content_sha256"] || result != expected["result"] ||
			!streamAcceptedAtMatches(expected["first_accepted_at"].(time.Time), accepted) {
			return fmt.Errorf("stream3 diagnostic receipt %s conflicts with segment: %w", key, streamlog.ErrContentConflict)
		}
		var saved, reference map[string]string
		if err := json.Unmarshal(rawRef, &saved); err != nil {
			return fmt.Errorf("stream3 diagnostic receipt %s has invalid reference: %w", key, streamlog.ErrContentConflict)
		}
		if err := json.Unmarshal(expected["body_ref"].(json.RawMessage), &reference); err != nil || !reflect.DeepEqual(saved, reference) {
			return fmt.Errorf("stream3 diagnostic receipt %s conflicts with segment reference: %w", key, streamlog.ErrContentConflict)
		}
		if state == "failed" {
			return fmt.Errorf("stream3 diagnostic receipt %s records archive failure: %w", key, streamlog.ErrUnconfirmed)
		}
	}
	return rows.Err()
}
