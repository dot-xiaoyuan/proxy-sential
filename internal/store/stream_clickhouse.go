package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type preparedStreamEvent struct {
	event     normalized.Event
	scope     string
	key       string
	hash      string
	body      string
	observed  time.Time
	retention string
}

func prepareStreamEvents(segment streamlog.Segment) ([]preparedStreamEvent, error) {
	if segment.Epoch == "" || segment.ArchiveMonth == "" || segment.AcceptedAt.IsZero() || len(segment.Events) == 0 {
		return nil, errors.New("stream segment lacks fixed epoch, archive month, acceptance time or events")
	}
	if _, err := time.Parse("200601", segment.ArchiveMonth); err != nil {
		return nil, err
	}
	prepared := make([]preparedStreamEvent, 0, len(segment.Events))
	seen := make(map[string]struct{}, len(segment.Events))
	if len(segment.EventOffsets) != 0 && len(segment.EventOffsets) != len(segment.Events) {
		return nil, errors.New("stream event offsets do not match event count")
	}
	if segment.KeyScheme != "" && segment.KeyScheme != "event_id_v1" && segment.KeyScheme != "source_position_v1" && segment.KeyScheme != "generation-v2" {
		return nil, errors.New("unknown stream event key scheme")
	}
	if segment.KeyScheme == "generation-v2" && (segment.Source != "zeek-dhcp-binding" || segment.ParserVersion != "zeek-dhcp-binding-v2" || segment.PreviousGeneration == 0 || segment.SourceGeneration < segment.PreviousGeneration || segment.SourceGeneration > segment.PreviousGeneration+1) {
		return nil, errors.New("invalid Zeek binding stream generation")
	}
	for index, event := range segment.Events {
		if event.EventID == "" {
			return nil, errors.New("stream event id is required")
		}
		observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("stream event %s has invalid timestamp: %w", event.EventID, err)
		}
		scope := streamScope(event)
		if scope == "" {
			return nil, fmt.Errorf("stream event %s lacks an explicit capture or identity scope", event.EventID)
		}
		key := segment.Epoch + ":" + event.EventID
		if segment.KeyScheme == "source_position_v1" {
			if segment.SourcePath == "" || segment.FileID == "" {
				return nil, errors.New("source-position stream key lacks path or file id")
			}
			offset := segment.StartOffset + int64(index)
			if len(segment.EventOffsets) != 0 {
				offset = segment.EventOffsets[index]
			}
			if offset < segment.StartOffset || offset >= segment.EndOffset {
				return nil, errors.New("source-position stream key is outside segment bounds")
			}
			sum := sha256.Sum256([]byte(segment.SourcePath + "\x00" + segment.FileID + "\x00" + strconv.FormatInt(offset, 10)))
			key = segment.Epoch + ":position:" + hex.EncodeToString(sum[:])
		}
		identity := scope + "\x00" + key
		if _, exists := seen[identity]; exists {
			return nil, fmt.Errorf("duplicate stream event key %s in one segment", event.EventID)
		}
		seen[identity] = struct{}{}
		body, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(body)
		retention := streamEventRetention(event)
		prepared = append(prepared, preparedStreamEvent{event: event, scope: scope, key: key, hash: hex.EncodeToString(hash[:]), body: string(body), observed: observed.UTC(), retention: retention})
	}
	return prepared, nil
}

// A mixed source segment can need projection for one event while containing
// high-volume diagnostics. Retention follows the event's actual business
// reader, not the segment-wide projection flag or the generic device type.
func streamEventRetention(event normalized.Event) string {
	if event.SourceEventType == "capture_coverage" {
		if event.Source == "handshake-sidecar" || event.Source == "packet-sidecar" {
			return "evidence"
		}
		return "short"
	}
	if normalized.IsDiscoveryProjectionEvent(event) {
		return "evidence"
	}
	switch event.Type {
	case "identity", "risk", "router":
		return "evidence"
	}
	if event.Source == "handshake-sidecar" && event.SourceEventType == "handshake" ||
		event.Source == "packet-sidecar" && (event.SourceEventType == "ieee1905_client_association" || event.SourceEventType == "ieee1905_client_snapshot") {
		return "evidence"
	}
	return "short"
}

func streamScope(event normalized.Event) string {
	if scope := stringFromMap(event.Observer, "capture_scope_id"); scope != "" {
		return scope
	}
	sensor := stringFromMap(event.Observer, "sensor_id")
	campus := stringFromMap(event.Subject, "campus_id")
	domain := stringFromMap(event.Payload, "access_domain")
	if sensor != "" && campus != "" && domain != "" {
		encoded, _ := json.Marshal([]string{sensor, campus, domain})
		sum := sha256.Sum256(encoded)
		return "identity:" + hex.EncodeToString(sum[:16])
	}
	return ""
}

// WriteStreamBody inserts immutable rows into exactly one authoritative body
// table per event. The normal path never scans ClickHouse for event IDs.
func (s *ClickHouseStore) WriteStreamBody(ctx context.Context, segmentID string, segment streamlog.Segment) error {
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return err
	}
	if streamRawArchiveRequired(segment) {
		if err := s.writeStreamRaw(ctx, segmentID, segment, prepared); err != nil {
			return err
		}
	}
	return s.writeStreamBodyEvents(ctx, segmentID, segmentID, segment, prepared, streamRawArchiveRequired(segment))
}

func streamRawArchiveRequired(segment streamlog.Segment) bool {
	return len(segment.Raw) > 0 && !segment.RawIsStandardEvents
}

func (s *ClickHouseStore) writeStreamBodyEvents(ctx context.Context, tokenID, rawSegmentID string, segment streamlog.Segment, prepared []preparedStreamEvent, hasRaw bool) error {
	archiveMonth, _ := strconv.ParseUint(segment.ArchiveMonth, 10, 32)
	for _, retention := range []string{"short", "evidence"} {
		var body bytes.Buffer
		table := "stream_event_body_" + retention
		body.WriteString("INSERT INTO " + table + " FORMAT JSONEachRow\n")
		rows := 0
		for _, item := range prepared {
			if item.retention != retention {
				continue
			}
			row := map[string]any{
				"archive_month": archiveMonth, "scope_id": item.scope,
				"event_key": item.key, "content_sha256": item.hash,
				"accepted_at": segment.AcceptedAt.UTC().Format("2006-01-02 15:04:05.000000"),
				"observed_at": item.observed.Format("2006-01-02 15:04:05.000000"),
				"source":      segment.Source, "parser_version": segment.ParserVersion,
				"source_path": segment.SourcePath, "file_id": segment.FileID,
				"start_offset": segment.StartOffset, "end_offset": segment.EndOffset,
				"raw_sha256": segment.RawSHA256, "body": item.body,
			}
			if hasRaw {
				row["raw_segment_id"] = rawSegmentID
			}
			if err := writeJSONLine(&body, row); err != nil {
				return err
			}
			rows++
		}
		if rows == 0 {
			continue
		}
		if _, err := s.queryWithSettings(ctx, body.String(), streamInsertSettings(tokenID, table)); err != nil {
			return fmt.Errorf("insert %s segment %s: %w", table, rawSegmentID, err)
		}
	}
	return nil
}

func (s *ClickHouseStore) writeStreamRaw(ctx context.Context, segmentID string, segment streamlog.Segment, prepared []preparedStreamEvent) error {
	sum := sha256.Sum256(segment.Raw)
	if segment.RawSHA256 != hex.EncodeToString(sum[:]) {
		return streamlog.ErrContentConflict
	}
	retention := "short"
	for _, item := range prepared {
		if item.retention == "evidence" {
			retention = "evidence"
			break
		}
	}
	month, _ := strconv.ParseUint(segment.ArchiveMonth, 10, 32)
	var body bytes.Buffer
	body.WriteString("INSERT INTO stream_source_raw FORMAT JSONEachRow\n")
	if err := writeJSONLine(&body, map[string]any{
		"archive_month": month, "segment_id": segmentID, "raw_sha256": segment.RawSHA256,
		"accepted_at":     segment.AcceptedAt.UTC().Format("2006-01-02 15:04:05.000000"),
		"retention_class": retention, "source": segment.Source,
		"source_path": segment.SourcePath, "file_id": segment.FileID,
		"start_offset": segment.StartOffset, "end_offset": segment.EndOffset,
		"raw_base64": base64.StdEncoding.EncodeToString(segment.Raw),
	}); err != nil {
		return err
	}
	_, err := s.queryWithSettings(ctx, body.String(), streamInsertSettings(segmentID, "stream_source_raw"))
	return err
}

// WriteStreamSearch stores only typed lookup fields and a stable body locator.
// It is a distinct acknowledgement from the authoritative body insert.
func (s *ClickHouseStore) WriteStreamSearch(ctx context.Context, segmentID string, segment streamlog.Segment) error {
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return err
	}
	archiveMonth, _ := strconv.ParseUint(segment.ArchiveMonth, 10, 32)
	var body bytes.Buffer
	body.WriteString("INSERT INTO stream_event_search FORMAT JSONEachRow\n")
	for _, item := range prepared {
		ref, _ := json.Marshal(StreamBodyRef{Class: item.retention, Month: segment.ArchiveMonth, Scope: item.scope, Key: item.key, SHA256: item.hash})
		routerScorePossible := uint8(1)
		if isPurePacketRouterTTL(item.event) {
			routerScorePossible = 0
		}
		row := map[string]any{
			"scope_id": item.scope, "event_key": item.key, "content_sha256": item.hash,
			"archive_month": archiveMonth, "retention_class": item.retention,
			"observed_at": item.observed.Format("2006-01-02 15:04:05.000000"),
			"protocol":    firstNonEmpty(item.event.SourceEventType, item.event.Source),
			"event_type":  item.event.Type, "source": item.event.Source,
			"router_score_possible": routerScorePossible,
			"sensor_id":             stringFromMap(item.event.Observer, "sensor_id"),
			"campus_id":             stringFromMap(item.event.Subject, "campus_id"),
			"access_domain":         stringFromMap(item.event.Payload, "access_domain"),
			"collector_instance_id": stringFromMap(item.event.Observer, "collector_instance_id"),
			"subject_ip":            stringFromMap(item.event.Subject, "ip"),
			"subject_mac":           stringFromMap(item.event.Subject, "mac"),
			"src_ip":                stringFromMap(item.event.Flow, "src_ip"),
			"dst_ip":                stringFromMap(item.event.Flow, "dst_ip"),
			"src_port":              uintFromMap(item.event.Flow, "src_port"),
			"dst_port":              uintFromMap(item.event.Flow, "dst_port"),
			"body_ref":              string(ref),
		}
		if err := writeJSONLine(&body, row); err != nil {
			return err
		}
	}
	_, err = s.queryWithSettings(ctx, body.String(), streamInsertSettings(segmentID, "stream_event_search"))
	return err
}

func streamInsertSettings(segmentID, table string) map[string]string {
	sum := sha256.Sum256([]byte(segmentID + "\x00" + table))
	return map[string]string{
		"async_insert": "1", "wait_for_async_insert": "1", "async_insert_deduplicate": "1",
		"insert_deduplicate": "1", "insert_deduplication_token": hex.EncodeToString(sum[:]),
	}
}

// VerifyStreamBody is for an ambiguous write result only. It constrains the
// check to the immutable month, scope and event keys; callers must retain the
// segment and stop the lane on a conflict or a partial result.
func (s *ClickHouseStore) VerifyStreamBody(ctx context.Context, segment streamlog.Segment) (bool, error) {
	missing, err := s.missingStreamBodyEvents(ctx, segment)
	if err != nil {
		return false, err
	}
	return len(missing) == 0, nil
}

// ReconcileStreamBody checks a bounded immutable segment after an ambiguous
// result, then writes only confirmed-missing rows. It never replays a row that
// the scoped check found under the same key and hash.
func (s *ClickHouseStore) ReconcileStreamBody(ctx context.Context, segmentID string, segment streamlog.Segment) error {
	if streamRawArchiveRequired(segment) {
		if err := s.reconcileStreamRaw(ctx, segmentID, segment); err != nil {
			return err
		}
	}
	missing, err := s.missingStreamBodyEvents(ctx, segment)
	if err != nil || len(missing) == 0 {
		return err
	}
	partial := segment
	partial.Events = make([]normalized.Event, 0, len(missing))
	partial.EventOffsets = make([]int64, 0, len(missing))
	var tokenKey strings.Builder
	for _, index := range missing {
		partial.Events = append(partial.Events, segment.Events[index])
		offset := segment.StartOffset + int64(index)
		if len(segment.EventOffsets) != 0 {
			offset = segment.EventOffsets[index]
		}
		partial.EventOffsets = append(partial.EventOffsets, offset)
		fmt.Fprintf(&tokenKey, "%d,", index)
	}
	token := sha256.Sum256([]byte(segmentID + "\x00" + tokenKey.String()))
	partial.Raw = nil
	prepared, err := prepareStreamEvents(partial)
	if err != nil {
		return err
	}
	if err := s.writeStreamBodyEvents(ctx, hex.EncodeToString(token[:]), segmentID, partial, prepared, streamRawArchiveRequired(segment)); err != nil {
		return err
	}
	confirmed, err := s.VerifyStreamBody(ctx, segment)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("stream body remains partially archived after scoped recovery")
	}
	return nil
}

func (s *ClickHouseStore) reconcileStreamRaw(ctx context.Context, segmentID string, segment streamlog.Segment) error {
	confirmed, err := s.verifyStreamRaw(ctx, segmentID, segment)
	if err != nil || confirmed {
		return err
	}
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return err
	}
	if err := s.writeStreamRaw(ctx, segmentID, segment, prepared); err != nil {
		return err
	}
	confirmed, err = s.verifyStreamRaw(ctx, segmentID, segment)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("stream raw source remains unarchived after scoped recovery")
	}
	return nil
}

func (s *ClickHouseStore) verifyStreamRaw(ctx context.Context, segmentID string, segment streamlog.Segment) (bool, error) {
	query := "SELECT raw_sha256,raw_base64 FROM stream_source_raw WHERE archive_month=" + segment.ArchiveMonth +
		" AND segment_id=" + chQuote(segmentID) + " FORMAT JSONEachRow"
	data, err := s.query(ctx, query)
	if err != nil {
		return false, err
	}
	found := false
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Hash string `json:"raw_sha256"`
			Raw  string `json:"raw_base64"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return false, err
		}
		raw, err := base64.StdEncoding.DecodeString(row.Raw)
		if err != nil {
			return false, err
		}
		sum := sha256.Sum256(raw)
		if row.Hash != segment.RawSHA256 || hex.EncodeToString(sum[:]) != segment.RawSHA256 {
			return false, streamlog.ErrContentConflict
		}
		found = true
	}
	return found, nil
}

func (s *ClickHouseStore) missingStreamBodyEvents(ctx context.Context, segment streamlog.Segment) ([]int, error) {
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return nil, err
	}
	missing := make([]int, 0)
	for _, retention := range []string{"short", "evidence"} {
		var keys []string
		expected := map[string]int{}
		remaining := map[string]int{}
		for index, item := range prepared {
			if item.retention != retention {
				continue
			}
			keys = append(keys, "("+chQuote(item.scope)+","+chQuote(item.key)+")")
			expected[item.scope+"\x00"+item.key] = index
			remaining[item.scope+"\x00"+item.key] = index
		}
		if len(keys) == 0 {
			continue
		}
		query := "SELECT scope_id,event_key,content_sha256 FROM stream_event_body_" + retention +
			" WHERE archive_month=" + segment.ArchiveMonth + " AND (scope_id,event_key) IN (" + strings.Join(keys, ",") + ") FORMAT JSONEachRow"
		data, err := s.query(ctx, query)
		if err != nil {
			return nil, err
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var row struct {
				Scope string `json:"scope_id"`
				Key   string `json:"event_key"`
				Hash  string `json:"content_sha256"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				return nil, err
			}
			key := row.Scope + "\x00" + row.Key
			index, found := expected[key]
			if !found || prepared[index].hash != row.Hash {
				return nil, streamlog.ErrContentConflict
			}
			delete(remaining, key)
		}
		for _, index := range remaining {
			missing = append(missing, index)
		}
	}
	return missing, nil
}

func (s *ClickHouseStore) VerifyStreamSearch(ctx context.Context, segment streamlog.Segment) (bool, error) {
	missing, err := s.missingStreamSearchEvents(ctx, segment)
	if err != nil {
		return false, err
	}
	return len(missing) == 0, nil
}

func (s *ClickHouseStore) ReconcileStreamSearch(ctx context.Context, segmentID string, segment streamlog.Segment) error {
	missing, err := s.missingStreamSearchEvents(ctx, segment)
	if err != nil || len(missing) == 0 {
		return err
	}
	partial := segment
	partial.Events = make([]normalized.Event, 0, len(missing))
	partial.EventOffsets = make([]int64, 0, len(missing))
	var tokenKey strings.Builder
	for _, index := range missing {
		partial.Events = append(partial.Events, segment.Events[index])
		offset := segment.StartOffset + int64(index)
		if len(segment.EventOffsets) != 0 {
			offset = segment.EventOffsets[index]
		}
		partial.EventOffsets = append(partial.EventOffsets, offset)
		fmt.Fprintf(&tokenKey, "%d,", index)
	}
	token := sha256.Sum256([]byte(segmentID + "\x00search\x00" + tokenKey.String()))
	if err := s.WriteStreamSearch(ctx, hex.EncodeToString(token[:]), partial); err != nil {
		return err
	}
	confirmed, err := s.VerifyStreamSearch(ctx, segment)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("stream search remains partially indexed after scoped recovery")
	}
	return nil
}

func (s *ClickHouseStore) missingStreamSearchEvents(ctx context.Context, segment streamlog.Segment) ([]int, error) {
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(prepared))
	expected := make(map[string]int, len(prepared))
	remaining := make(map[string]int, len(prepared))
	minTime, maxTime := prepared[0].observed, prepared[0].observed
	for index, item := range prepared {
		keys = append(keys, "("+chQuote(item.scope)+","+chQuote(item.key)+")")
		expected[item.scope+"\x00"+item.key] = index
		remaining[item.scope+"\x00"+item.key] = index
		if item.observed.Before(minTime) {
			minTime = item.observed
		}
		if item.observed.After(maxTime) {
			maxTime = item.observed
		}
	}
	query := "SELECT scope_id,event_key,content_sha256,archive_month,retention_class FROM stream_event_search PREWHERE observed_at >= " +
		chQuote(minTime.Format("2006-01-02 15:04:05.000000")) + " AND observed_at <= " + chQuote(maxTime.Format("2006-01-02 15:04:05.000000")) +
		" AND (scope_id,event_key) IN (" + strings.Join(keys, ",") + ")" +
		fmt.Sprintf(" LIMIT %d SETTINGS max_threads=1,max_memory_usage=134217728,max_execution_time=5 FORMAT JSONEachRow", 101*len(prepared))
	data, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]int, len(expected))
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Scope string `json:"scope_id"`
			Key   string `json:"event_key"`
			Hash  string `json:"content_sha256"`
			Month uint32 `json:"archive_month"`
			Class string `json:"retention_class"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, err
		}
		key := row.Scope + "\x00" + row.Key
		index, found := expected[key]
		if !found || prepared[index].hash != row.Hash || fmt.Sprint(row.Month) != segment.ArchiveMonth || prepared[index].retention != row.Class || seen[key] >= 100 {
			return nil, streamlog.ErrContentConflict
		}
		seen[key]++
		delete(remaining, key)
	}
	missing := make([]int, 0, len(remaining))
	for _, index := range remaining {
		missing = append(missing, index)
	}
	return missing, nil
}
