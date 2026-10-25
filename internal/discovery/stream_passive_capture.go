package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

const PassiveStreamParserVersion = "passive-frame-v1"

func PassiveStreamSourcePath(source Source) string {
	return "packet://" + source.Address + "/" + source.ID
}

// AppendPassiveStreamBatch is the durable boundary for non-file passive
// observations. The segment owns the standard events once; packet bytes were
// never retained, so this source must not claim packet-level provenance.
func AppendPassiveStreamBatch(ctx context.Context, journal *streamlog.Journal, source Source, scope *normalized.CaptureScope, events []normalized.Event) (string, error) {
	if journal == nil || scope == nil || source.ID == "" || source.Address == "" || len(events) == 0 || len(events) > streamlog.MaxSegmentEvents {
		return "", errors.New("passive stream requires a bounded batch, source and capture scope")
	}
	if source.Node != scope.SensorID || source.Site != scope.CampusID || source.Domain != scope.AccessDomain || source.Address != scope.InterfaceName || scope.CollectorInstanceID == "" ||
		scope.SchemaVersion != "capture-scope/v1" || !scope.ValidUntil.After(scope.ValidFrom) {
		return "", errors.New("passive stream source does not match controlled capture scope")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path := PassiveStreamSourcePath(source)
	cursor, err := journal.LoadSource("passive-discovery", path)
	if err != nil {
		return "", err
	}
	if cursor.ParserVersion != PassiveStreamParserVersion || cursor.Epoch == "" {
		return "", streamlog.ErrContentConflict
	}
	start := cursor.Offset
	if cursor.FileID != scope.CollectorInstanceID {
		start = 0
	}
	prepared := make([]normalized.Event, 0, len(events))
	for _, event := range events {
		if event.Type != "discovery" || event.EventID == "" || event.Timestamp == "" {
			return "", errors.New("passive stream batch contains unsupported event")
		}
		copy := event
		copy.Observer = cloneStreamFields(event.Observer)
		copy.Observer["collector_instance_id"] = scope.CollectorInstanceID
		copy = scope.Apply(copy)
		if issue, _ := copy.Observer["capture_scope_issue"].(string); issue != "" {
			return "", fmt.Errorf("passive stream capture scope: %s", issue)
		}
		if copy.Observer["capture_scope_id"] == "" {
			return "", errors.New("passive stream event has no capture scope")
		}
		prepared = append(prepared, copy)
	}
	raw, err := json.Marshal(prepared)
	if err != nil {
		return "", err
	}
	for index := range prepared {
		original := prepared[index].EventID
		identity, _ := json.Marshal([]any{cursor.Epoch, "passive-discovery", path, scope.CollectorInstanceID, start, index})
		sum := sha256.Sum256(identity)
		prepared[index].EventID = "stream-" + hex.EncodeToString(sum[:16])
		prepared[index].RawRef = cloneStreamFields(prepared[index].RawRef)
		prepared[index].RawRef["backend"] = "passive-discovery"
		prepared[index].RawRef["producer_event_id"] = original
		prepared[index].RawRef["source_offset"] = start
		prepared[index].RawRef["source_record_ordinal"] = index
		prepared[index].RawRef["raw_packet_available"] = false
	}
	now := time.Now().UTC()
	segment := streamlog.Segment{Epoch: cursor.Epoch, Source: "passive-discovery", SourcePath: path,
		PreviousFileID: cursor.FileID, PreviousOffset: cursor.Offset, FileID: scope.CollectorInstanceID,
		StartOffset: start, EndOffset: start + int64(len(raw)), ParserVersion: PassiveStreamParserVersion,
		ArchiveMonth: now.Format("200601"), AcceptedAt: now,
		NeedsProjection: true, Events: prepared}
	id, err := journal.Append(segment)
	if err != nil {
		return "", err
	}
	if err := journal.CommitSource("passive-discovery", path, id); err != nil {
		return id, err
	}
	return id, nil
}

func cloneStreamFields(fields map[string]any) map[string]any {
	copy := make(map[string]any, len(fields)+4)
	for key, value := range fields {
		copy[key] = value
	}
	return copy
}
