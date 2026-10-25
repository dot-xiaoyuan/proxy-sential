package realtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/streamlog"
)

var ErrStreamSourceGap = errors.New("stream source has an unconfirmed file gap or truncation")
var ErrStreamArchivePending = errors.New("Zeek rotated archive is not yet available for verification")

const streamReadLimit = 1 << 20
const streamLineLimit = streamlog.MaxSegmentEvents
const discoveryStreamLineLimit = 50

// CaptureStreamOnce only advances a pre-established fresh source cursor after
// its exact raw bytes and normalized events are fsynced in an immutable segment.
// It does not establish a fresh cutoff or process downstream acknowledgements.
func CaptureStreamOnce(ctx context.Context, journal *streamlog.Journal, opts Options, source Source) (string, bool, error) {
	if journal == nil || opts.SensorID == "" || source.Kind == "" || source.Path == "" {
		return "", false, errors.New("stream capture requires journal, sensor and source")
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	cursor, err := journal.LoadSource(source.Kind, source.Path)
	if err != nil {
		return "", false, err
	}
	if source.Kind == "zeek-dhcp-binding" && cursor.Offset > 0 && cursor.TailBytes == 0 {
		if tail, proofErr := currentZeekTailProof(source.Path, cursor); proofErr == nil {
			if err := journal.SetSourceTailProof(source.Kind, source.Path, cursor.FileID, cursor.Offset, tail); err != nil {
				return "", false, err
			}
			cursor, err = journal.LoadSource(source.Kind, source.Path)
			if err != nil {
				return "", false, err
			}
		}
	}
	maxBytes := opts.MaxBatchBytes
	if maxBytes <= 0 || maxBytes > streamReadLimit {
		maxBytes = streamReadLimit
	}
	checkpoint := ingest.Checkpoint{FileID: cursor.FileID, Offset: cursor.Offset}
	var read sourceChunk
	if source.Kind == "zeek-dhcp-binding" {
		read, err = readZeekBindingChunk(source.Path, cursor, maxBytes)
	} else {
		read, err = readSourceChunk(source.Path, checkpoint, true, maxBytes, strings.HasPrefix(source.Kind, "zeek-"))
	}
	if err != nil {
		return "", false, err
	}
	if err := validateStreamRead(source.Path, cursor.FileID, cursor.Offset, read, cursor.KeyScheme == "generation-v2"); err != nil {
		return "", false, err
	}
	generation := cursor.Generation
	if cursor.KeyScheme == "generation-v2" {
		if generation == 0 {
			return "", false, streamlog.ErrContentConflict
		}
		if read.verifiedRotation {
			generation++
		}
	}
	if len(read.data) == 0 {
		if sourceLag(source.Path, cursor.FileID, cursor.Offset) >= maxBytes {
			return "", false, fmt.Errorf("source record exceeds stream read limit: %w", streamlog.ErrSegmentTooLarge)
		}
		return "", false, nil
	}
	chunk := read.data
	lineLimit := streamLineLimit
	// DHCP always updates the device projection. Other controlled signal
	// sources may contain only archive or risk events and can use larger
	// ClickHouse batches; a selected discovery event below still caps them.
	if source.Kind == "zeek-dhcp" || source.Kind == "zeek-dhcp-binding" {
		lineLimit = discoveryStreamLineLimit
	}
	if end := lineBoundary(chunk, lineLimit); end < len(chunk) {
		chunk = chunk[:end]
	}
	for {
		events, stats, err := normalize(source, chunk, read.start, opts.SensorID, read.header)
		if err != nil {
			return quarantineStreamChunk(journal, cursor, source, read, chunk, "parser_error", err)
		}
		if stats.Malformed > 0 {
			return quarantineStreamChunk(journal, cursor, source, read, chunk, "malformed_record", fmt.Errorf("source %s at offset %d has %d malformed records", source.Kind, read.start, stats.Malformed))
		}
		benign := benignStreamSkips(source.Kind, chunk, read.start, read.header)
		if stats.Skipped > benign {
			return quarantineStreamChunk(journal, cursor, source, read, chunk, "rejected_record", fmt.Errorf("source %s at offset %d has %d unsupported or rejected records", source.Kind, read.start, stats.Skipped-benign))
		}
		if len(events) > discoveryStreamLineLimit && needsStreamProjection(events) {
			if end := lineBoundary(chunk, discoveryStreamLineLimit); end < len(chunk) {
				chunk = chunk[:end]
			} else if chunk, err = smallerWholeLineChunk(chunk); err != nil {
				return "", false, err
			}
			continue
		}
		if (source.Kind == "device-signals" || source.Kind == "shared-device-signals") && source.CaptureScope != nil {
			if err := validateControlledStreamSignals(chunk, events, source.CaptureScope, source.ControlledInterface); err != nil {
				return quarantineStreamChunk(journal, cursor, source, read, chunk, "capture_scope_mismatch", err)
			}
		}
		if len(events) > streamlog.MaxSegmentEvents {
			if chunk, err = smallerWholeLineChunk(chunk); err != nil {
				return "", false, err
			}
			continue
		}
		if err := assignStreamPositionKeys(events, source, cursor.Epoch, read.fileID, read.start, chunk, generation); err != nil {
			return quarantineStreamChunk(journal, cursor, source, read, chunk, "position_mapping_error", err)
		}
		rawHash := sha256.Sum256(chunk)
		segment := streamlog.Segment{
			Epoch: cursor.Epoch, Source: source.Kind, SourcePath: source.Path,
			PreviousFileID: cursor.FileID, PreviousOffset: cursor.Offset,
			FileID: read.fileID, StartOffset: read.start, EndOffset: read.start + int64(len(chunk)),
			ParserVersion: cursor.ParserVersion, RawSHA256: hex.EncodeToString(rawHash[:]),
			KeyScheme: cursor.KeyScheme, PreviousGeneration: cursor.Generation, SourceGeneration: generation,
			ArchiveMonth: time.Now().UTC().Format("200601"), AcceptedAt: time.Now().UTC(),
			NeedsProjection: needsStreamProjection(events), RiskFeaturesRequired: len(events) > 0, Raw: chunk, Events: events,
		}
		segment.RawIsStandardEvents = source.Kind == "device-signals" || source.Kind == "shared-device-signals"
		segment.SourceBackedRaw = source.Kind == "zeek-dhcp-binding" && journal.HasRawResolver()
		appendStarted := time.Now()
		id, err := journal.Append(segment)
		if elapsed := time.Since(appendStarted); elapsed >= 500*time.Millisecond {
			log.Printf("stream capture stage source=%s events=%d stage=append duration=%s", source.Kind, len(events), elapsed.Round(time.Millisecond))
		}
		if errors.Is(err, streamlog.ErrSegmentTooLarge) {
			if chunk, err = smallerWholeLineChunk(chunk); err != nil {
				return "", false, err
			}
			continue
		}
		if err != nil {
			return "", false, err
		}
		commitStarted := time.Now()
		if err := journal.CommitSource(source.Kind, source.Path, id); err != nil {
			return id, false, err
		}
		if elapsed := time.Since(commitStarted); elapsed >= 500*time.Millisecond {
			log.Printf("stream capture stage source=%s events=%d stage=commit_cursor duration=%s", source.Kind, len(events), elapsed.Round(time.Millisecond))
		}
		return id, true, nil
	}
}

// A producer-owned device signal already carries its observation scope. The
// stream reader must not rebind an old or unscoped JSON line to today's scope.
func validateControlledStreamSignals(chunk []byte, events []normalized.Event, scope *normalized.CaptureScope, controlledInterface string) error {
	if scope == nil {
		return errors.New("device signal capture scope is required")
	}
	if controlledInterface == "" {
		controlledInterface = scope.InterfaceName
	}
	if controlledInterface == "" || (scope.InterfaceName != "" && controlledInterface != scope.InterfaceName) {
		return errors.New("device signal needs a controlled interface")
	}
	lines := bytes.Split(bytes.TrimSuffix(chunk, []byte{'\n'}), []byte{'\n'})
	if len(lines) != len(events) {
		return errors.New("device signal source positions do not match events")
	}
	for index, line := range lines {
		var original normalized.Event
		if err := json.Unmarshal(line, &original); err != nil {
			return err
		}
		event := events[index]
		if original.Observer == nil || original.Observer["sensor_id"] != scope.SensorID ||
			original.Observer["capture_scope_id"] == "" ||
			original.Observer["collector_instance_id"] != scope.CollectorInstanceID ||
			original.Observer["interface"] != controlledInterface ||
			event.Subject["campus_id"] != scope.CampusID || event.Payload["access_domain"] != scope.AccessDomain {
			return fmt.Errorf("device signal at line %d has no matching producer-owned scope", index+1)
		}
		mapped := scope.Apply(event)
		if mapped.Observer["capture_scope_issue"] != nil || mapped.Observer["capture_scope_id"] != original.Observer["capture_scope_id"] {
			return fmt.Errorf("device signal at line %d conflicts with controlled capture scope", index+1)
		}
	}
	return nil
}

// The legacy adapters identify records by their raw content. A stream event
// instead represents one immutable source position: identical records at two
// offsets must both be archived, acknowledged and available for evidence.
func assignStreamPositionKeys(events []normalized.Event, source Source, epoch, fileID string, startOffset int64, chunk []byte, generation ...uint64) error {
	var sourceGeneration uint64
	if len(generation) > 0 {
		sourceGeneration = generation[0]
	}
	positions := make([]int64, 0, len(events))
	allLines := make([]int64, 0, len(events))
	zeek := strings.HasPrefix(source.Kind, "zeek-")
	for start := 0; start < len(chunk); {
		end := bytes.IndexByte(chunk[start:], '\n')
		if end < 0 {
			return fmt.Errorf("stream chunk has an incomplete source line at %d", startOffset+int64(start))
		}
		end += start
		allLines = append(allLines, startOffset+int64(start))
		line := bytes.TrimSpace(chunk[start:end])
		if len(line) > 0 && !(zeek && line[0] == '#') {
			positions = append(positions, startOffset+int64(start))
		}
		start = end + 1
	}
	if source.Kind != "suricata" && len(positions) != len(events) {
		return fmt.Errorf("stream source position mapping mismatch: %d records, %d events", len(positions), len(events))
	}
	seen := make(map[string]bool, len(events))
	for i := range events {
		position := int64(0)
		variant := ""
		if source.Kind == "suricata" {
			ordinal, ok := streamLineOrdinal(events[i].RawRef["line_offset"])
			if !ok || ordinal < 1 || ordinal > len(allLines) {
				return fmt.Errorf("suricata event %d has no matching source line", i)
			}
			position = allLines[ordinal-1]
			variant = events[i].Type
		} else {
			position = positions[i]
		}
		identity := []byte(epoch + "\x00" + source.Kind + "\x00" + source.Path + "\x00" + fileID + "\x00" + strconv.FormatInt(position, 10) + "\x00" + variant)
		if sourceGeneration > 0 {
			identity = append(identity, []byte("\x00generation:"+strconv.FormatUint(sourceGeneration, 10))...)
		}
		if seen[string(identity)] {
			return fmt.Errorf("multiple stream events at one source position and variant")
		}
		seen[string(identity)] = true
		sum := sha256.Sum256(identity)
		if events[i].RawRef == nil {
			events[i].RawRef = map[string]any{}
		}
		events[i].RawRef["producer_event_id"] = events[i].EventID
		events[i].RawRef["source_offset"] = position
		events[i].EventID = "stream-" + hex.EncodeToString(sum[:16])
		if events[i].Type == "proxy_transaction" && source.ProxyProducer != nil {
			if err := proxyprotocol.Sign(&events[i], *source.ProxyProducer); err != nil {
				return fmt.Errorf("re-sign stream proxy event: %w", err)
			}
		}
	}
	return nil
}

func streamLineOrdinal(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), int64(int(v)) == v
	case float64:
		n := int(v)
		return n, float64(n) == v
	default:
		return 0, false
	}
}

func quarantineStreamChunk(journal *streamlog.Journal, cursor streamlog.SourceCursor, source Source, read sourceChunk, chunk []byte, reason string, cause error) (string, bool, error) {
	sum := sha256.Sum256(chunk)
	now := time.Now().UTC()
	generation := cursor.Generation
	if cursor.KeyScheme == "generation-v2" && read.verifiedRotation {
		generation++
	}
	id, err := journal.Append(streamlog.Segment{
		Epoch: cursor.Epoch, Source: source.Kind, SourcePath: source.Path,
		PreviousFileID: cursor.FileID, PreviousOffset: cursor.Offset,
		FileID: read.fileID, StartOffset: read.start, EndOffset: read.start + int64(len(chunk)),
		ParserVersion: cursor.ParserVersion, RawSHA256: hex.EncodeToString(sum[:]),
		KeyScheme: cursor.KeyScheme, PreviousGeneration: cursor.Generation, SourceGeneration: generation,
		ArchiveMonth: now.Format("200601"), AcceptedAt: now,
		Quarantined: true, QuarantineReason: reason, Raw: chunk,
	})
	if err != nil {
		return "", false, errors.Join(cause, err)
	}
	return id, false, errors.Join(streamlog.ErrQuarantined, cause)
}

func benignStreamSkips(kind string, chunk []byte, offset int64, header []byte) int {
	zeek := strings.HasPrefix(kind, "zeek-")
	count := 0
	countLines := func(data []byte) {
		for _, line := range bytes.Split(data, []byte{'\n'})[:bytes.Count(data, []byte{'\n'})] {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) == 0 || (zeek && trimmed[0] == '#') {
				count++
			}
		}
	}
	countLines(chunk)
	if zeek && offset > 0 {
		countLines(append(append([]byte(nil), header...), '\n'))
	}
	return count
}

func needsStreamProjection(events []normalized.Event) bool {
	for _, event := range events {
		if normalized.IsDiscoveryProjectionEvent(event) {
			return true
		}
		switch event.Type {
		case "identity", "risk", "router":
			return true
		}
	}
	return false
}

func lineBoundary(data []byte, maxLines int) int {
	if maxLines <= 0 {
		return len(data)
	}
	position := 0
	for i := 0; i < maxLines; i++ {
		index := bytes.IndexByte(data[position:], '\n')
		if index < 0 {
			return len(data)
		}
		position += index + 1
	}
	return position
}

func smallerWholeLineChunk(data []byte) ([]byte, error) {
	lines := bytes.Count(data, []byte{'\n'})
	if lines <= 1 {
		return nil, streamlog.ErrSegmentTooLarge
	}
	return data[:lineBoundary(data, lines/2)], nil
}

func validateStreamRead(path, oldFileID string, oldOffset int64, read sourceChunk, allowReusedInode ...bool) error {
	allowSameFile := len(allowReusedInode) > 0 && allowReusedInode[0]
	if read.verifiedRotation && !read.truncated && (read.fileID != oldFileID || allowSameFile) && read.start == 0 {
		return nil
	}
	if !read.truncated && read.fileID == oldFileID && read.start == oldOffset {
		return nil
	}
	if read.start != 0 || read.fileID == oldFileID {
		return ErrStreamSourceGap
	}
	// A new file is safe only while the previous file still exists and its
	// exact size equals the committed cursor. Missing rotated files are gaps.
	paths := append([]string{path}, rotatedSourceCandidates(path)...)
	for _, candidate := range paths {
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if fileIdentity(path, info) == oldFileID {
			if info.Size() == oldOffset {
				return nil
			}
			return ErrStreamSourceGap
		}
	}
	return ErrStreamSourceGap
}
