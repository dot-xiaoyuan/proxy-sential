package realtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/store"
)

type Source struct {
	CaptureScope        *normalized.CaptureScope
	ProxyProducer       *proxyprotocol.Producer
	Kind                string
	Path                string
	CollectorInstanceID string
}

type Options struct {
	SensorID      string
	Sources       []Source
	PollInterval  time.Duration
	MaxBatchBytes int64
	StoreTimeout  time.Duration
	AlertWebhook  string
	Heartbeat     time.Duration
	AlertLagBytes int64
	AlertBadRate  float64
}

type Backend interface {
	WriteCollectorRun(context.Context, store.Run) error
	WriteNormalizedEvents(context.Context, []normalized.Event) error
	WriteIngestDiagnostics(context.Context, []ingest.Diagnostic) error
	LoadIngestCheckpoint(context.Context, string, string) (ingest.Checkpoint, bool, error)
	BeginIngestBatch(context.Context, ingest.Batch) error
	CommitIngestBatch(context.Context, ingest.Batch, string) error
	FailIngestBatch(context.Context, string, error) error
}

func Run(ctx context.Context, backend Backend, opts Options) error {
	if backend == nil {
		return fmt.Errorf("ingest backend is required")
	}
	if opts.SensorID == "" {
		return fmt.Errorf("sensor id is required")
	}
	if len(opts.Sources) == 0 {
		return fmt.Errorf("at least one ingest source is required")
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.MaxBatchBytes <= 0 {
		opts.MaxBatchBytes = 8 << 20
	}
	if opts.StoreTimeout <= 0 {
		opts.StoreTimeout = 2 * time.Minute
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = 30 * time.Second
	}
	if opts.AlertLagBytes <= 0 {
		opts.AlertLagBytes = 64 << 20
	}
	if opts.AlertBadRate <= 0 {
		opts.AlertBadRate = 0.01
	}
	if locker, ok := backend.(interface {
		AcquireIngestSourceLease(context.Context, string, string) (func(), error)
	}); ok {
		releases := make([]func(), 0, len(opts.Sources))
		for _, source := range opts.Sources {
			if source.Path == "" {
				continue
			}
			release, err := locker.AcquireIngestSourceLease(ctx, source.Kind, source.Path)
			if err != nil {
				for index := len(releases) - 1; index >= 0; index-- {
					releases[index]()
				}
				return err
			}
			releases = append(releases, release)
		}
		defer func() {
			for index := len(releases) - 1; index >= 0; index-- {
				releases[index]()
			}
		}()
	}
	lastAlert := map[string]time.Time{}
	lastHeartbeat := map[string]time.Time{}
	for {
		for _, source := range opts.Sources {
			if ctx.Err() != nil {
				return nil
			}
			key := source.Kind + "\x00" + source.Path
			consumed, err := processOnce(ctx, backend, opts, source)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				// A failed source must not stop healthy sources. Record failures even
				// without a webhook; a source error is never a healthy heartbeat.
				if time.Since(lastAlert[key]) >= 5*time.Minute {
					log.Printf("realtime ingest source failed; retry scheduled: kind=%q path=%q", source.Kind, source.Path)
					_ = writeSourceFailure(ctx, backend, opts, source, err)
					sendAlert(ctx, opts.AlertWebhook, opts.SensorID, source, err)
					lastAlert[key] = time.Now()
				}
				continue
			}
			if !consumed && time.Since(lastHeartbeat[key]) >= opts.Heartbeat {
				if err := writeHeartbeat(ctx, backend, opts, source); err != nil && time.Since(lastAlert[key]) >= 5*time.Minute {
					sendAlert(ctx, opts.AlertWebhook, opts.SensorID, source, err)
					lastAlert[key] = time.Now()
				} else if err == nil {
					lastHeartbeat[key] = time.Now()
				}
			}
		}
		timer := time.NewTimer(opts.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func sendAlert(ctx context.Context, endpoint, sensorID string, source Source, cause error) {
	if strings.TrimSpace(endpoint) == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{"type": "ingest_failure", "sensor_id": sensorID, "source_kind": source.Kind, "source_path": source.Path, "error": cause.Error(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err == nil {
		response.Body.Close()
	}
}

func ProcessOnce(ctx context.Context, backend Backend, opts Options, source Source) error {
	_, err := processOnce(ctx, backend, opts, source)
	return err
}

func processOnce(ctx context.Context, backend Backend, opts Options, source Source) (bool, error) {
	if source.Path == "" {
		return false, nil
	}
	checkpoint, found, err := backend.LoadIngestCheckpoint(ctx, source.Kind, source.Path)
	if err != nil {
		return false, err
	}
	read, err := readSourceChunk(source.Path, checkpoint, found, opts.MaxBatchBytes, strings.HasPrefix(source.Kind, "zeek-"))
	chunk, fileID, start, end, truncated := read.data, read.fileID, read.start, read.end, read.truncated
	if err != nil {
		return false, err
	}
	if len(chunk) == 0 {
		return false, nil
	}
	events, stats, err := normalize(source, chunk, start, opts.SensorID, read.header)
	if err != nil {
		return false, err
	}
	checksumBytes := sha256.Sum256(chunk)
	checksum := hex.EncodeToString(checksumBytes[:])
	batchID := stableID(opts.SensorID, source.Kind, source.Path, fileID, fmt.Sprint(start), fmt.Sprint(end), checksum)
	now := time.Now().UTC()
	batch := ingest.Batch{BatchID: batchID, SensorID: opts.SensorID, SourceKind: source.Kind, SourcePath: source.Path, FileID: fileID, StartOffset: start, EndOffset: end, Checksum: checksum, Status: "started", StartedAt: now.Format(time.RFC3339Nano)}
	if err := backend.BeginIngestBatch(ctx, batch); err != nil {
		return false, err
	}
	failed := func(cause error) error {
		// A failed/expired event-write context cannot be reused for the audit,
		// but its detached context must still have a bounded lifetime.
		auditCtx, auditCancel := context.WithTimeout(context.Background(), failureReportingTimeout(opts.StoreTimeout))
		defer auditCancel()
		_ = backend.FailIngestBatch(auditCtx, batchID, cause)
		return cause
	}
	writeCtx, cancel := context.WithTimeout(ctx, opts.StoreTimeout)
	defer cancel()
	eventWriteStarted := time.Now()
	if err := backend.WriteNormalizedEvents(writeCtx, events); err != nil {
		return false, failed(err)
	}
	finished := time.Now().UTC()
	eventWriteDuration := time.Since(eventWriteStarted)
	lagBytes := sourceLag(source.Path, fileID, end)
	diagnostic := ingest.Diagnostic{
		SchemaVersion: "v1", DiagnosticID: "diag-" + batchID, Timestamp: finished.Format(time.RFC3339Nano), SensorID: opts.SensorID,
		Collector: ingest.Collector{Kind: source.Kind}, Stage: "realtime_ingest", Type: "batch", Severity: severity(stats, truncated),
		Summary: summary(stats, truncated), Counters: map[string]int{"read": stats.Read, "emitted": stats.Emitted, "skipped": stats.Skipped, "malformed": stats.Malformed}, ByType: stats.ByType,
		RawRef:  map[string]any{"source": source.Path, "file_id": fileID, "start_offset": start, "end_offset": end},
		Details: map[string]any{"batch_id": batchID, "lag_bytes": lagBytes, "truncated": truncated, "archive_draining": read.archive, "clickhouse_event_write_ms": eventWriteDuration.Milliseconds(), "write_duration_ms": time.Since(now).Milliseconds()},
	}
	run := store.Run{RunID: batchID, StartedAt: now.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano), SensorID: opts.SensorID, PreviousOffset: start, NewOffset: end, Truncated: truncated, Normalized: store.NormalizedCounts{Read: stats.Read, Emitted: stats.Emitted, Skipped: stats.Skipped, Malformed: stats.Malformed, ByType: stats.ByType}, RawRef: diagnostic.RawRef}
	postgresWriteStarted := time.Now()
	if err := backend.WriteCollectorRun(writeCtx, run); err != nil {
		return false, failed(err)
	}
	diagnostic.Details["postgres_collector_write_ms"] = time.Since(postgresWriteStarted).Milliseconds()
	if err := backend.WriteIngestDiagnostics(writeCtx, []ingest.Diagnostic{diagnostic}); err != nil {
		return false, failed(err)
	}
	batch.Status = "committed"
	batch.EventCount = len(events)
	batch.Malformed = stats.Malformed
	batch.CommittedAt = finished.Format(time.RFC3339Nano)
	if err := backend.CommitIngestBatch(writeCtx, batch, latestTimestamp(events)); err != nil {
		return false, failed(err)
	}
	if lagBytes > opts.AlertLagBytes {
		sendAlert(ctx, opts.AlertWebhook, opts.SensorID, source, fmt.Errorf("ingest lag %d bytes exceeds threshold %d", lagBytes, opts.AlertLagBytes))
	}
	if stats.Read > 0 && float64(stats.Malformed)/float64(stats.Read) > opts.AlertBadRate {
		sendAlert(ctx, opts.AlertWebhook, opts.SensorID, source, fmt.Errorf("malformed rate %.4f exceeds threshold %.4f", float64(stats.Malformed)/float64(stats.Read), opts.AlertBadRate))
	}
	return true, nil
}

func failureReportingTimeout(storeTimeout time.Duration) time.Duration {
	if storeTimeout <= 0 || storeTimeout > 5*time.Second {
		return 5 * time.Second
	}
	return storeTimeout
}

// Failure reporting is bounded separately so unavailable diagnostic storage
// cannot add the full event-write timeout before polling other sources.
func writeSourceFailure(ctx context.Context, backend Backend, opts Options, source Source, cause error) error {
	now := time.Now().UTC()
	diagnostic := ingest.Diagnostic{
		SchemaVersion: "v1", DiagnosticID: "diag-" + stableID(opts.SensorID, source.Kind, source.Path, "source_error", now.Format(time.RFC3339Nano)),
		Timestamp: now.Format(time.RFC3339Nano), SensorID: opts.SensorID, Collector: ingest.Collector{Kind: source.Kind},
		Stage: "realtime_ingest", Type: "source_error", Severity: "error", Summary: "source ingest failed; retry required",
		RawRef: map[string]any{"source": source.Path}, Details: map[string]any{"error": cause.Error()},
	}
	writeCtx, cancel := context.WithTimeout(ctx, failureReportingTimeout(opts.StoreTimeout))
	defer cancel()
	return backend.WriteIngestDiagnostics(writeCtx, []ingest.Diagnostic{diagnostic})
}

func writeHeartbeat(ctx context.Context, backend Backend, opts Options, source Source) error {
	checkpoint, _, err := backend.LoadIngestCheckpoint(ctx, source.Kind, source.Path)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	id := stableID(opts.SensorID, source.Kind, source.Path, "heartbeat", now.Truncate(opts.Heartbeat).Format(time.RFC3339Nano))
	diagnostic := ingest.Diagnostic{SchemaVersion: "v1", DiagnosticID: "diag-" + id, Timestamp: now.Format(time.RFC3339Nano), SensorID: opts.SensorID, Collector: ingest.Collector{Kind: source.Kind}, Stage: "realtime_ingest", Type: "heartbeat", Severity: "info", Summary: "source active; no complete records pending", Counters: map[string]int{"read": 0, "emitted": 0, "skipped": 0, "malformed": 0}, RawRef: map[string]any{"source": source.Path, "file_id": checkpoint.FileID, "offset": checkpoint.Offset}, Details: map[string]any{"lag_bytes": sourceLag(source.Path, checkpoint.FileID, checkpoint.Offset)}}
	writeCtx, cancel := context.WithTimeout(ctx, opts.StoreTimeout)
	defer cancel()
	if err := backend.WriteIngestDiagnostics(writeCtx, []ingest.Diagnostic{diagnostic}); err != nil {
		return err
	}
	return backend.WriteCollectorRun(writeCtx, store.Run{RunID: id, StartedAt: now.Format(time.RFC3339Nano), FinishedAt: now.Format(time.RFC3339Nano), SensorID: opts.SensorID, PreviousOffset: checkpoint.Offset, NewOffset: checkpoint.Offset, Normalized: store.NormalizedCounts{ByType: map[string]int{}}, RawRef: diagnostic.RawRef})
}

type normalizedStats struct {
	Read, Emitted, Skipped, Malformed int
	ByType                            map[string]int
}

func normalize(source Source, chunk []byte, absoluteOffset int64, sensorID string, header []byte) ([]normalized.Event, normalizedStats, error) {
	input := chunk
	if strings.HasPrefix(source.Kind, "zeek-") && absoluteOffset > 0 {
		input = append(append(header, '\n'), chunk...)
	}
	var output bytes.Buffer
	stats := normalizedStats{ByType: map[string]int{}}
	switch source.Kind {
	case "suricata":
		value, err := suricata.Convert(bytes.NewReader(input), &output, suricata.Options{CaptureScope: source.CaptureScope, SensorID: sensorID, CollectorInstanceID: source.CollectorInstanceID, ProxyProducer: source.ProxyProducer})
		stats = normalizedStats{Read: value.Read, Emitted: value.Emitted, Skipped: value.Skipped, Malformed: value.Malformed, ByType: value.ByType}
		if err != nil {
			return nil, stats, err
		}
	case "zeek-proxy", "zeek-dhcp", "zeek-software", "zeek-mdns", "zeek-nbns", "zeek-llmnr", "zeek-ttl", "zeek-conn", "zeek-dns", "zeek-http", "zeek-ssl", "zeek-x509", "zeek-lldp", "zeek-ssdp", "zeek-snmp":
		value, err := zeek.Convert(bytes.NewReader(input), &output, zeek.Options{CaptureScope: source.CaptureScope, SensorID: sensorID, LogKind: strings.TrimPrefix(source.Kind, "zeek-"), CollectorInstanceID: source.CollectorInstanceID, ProxyProducer: source.ProxyProducer})
		stats = normalizedStats{Read: value.Read, Emitted: value.Emitted, Skipped: value.Skipped, Malformed: value.Malformed, ByType: value.ByType}
		if err != nil {
			return nil, stats, err
		}
	case "device-signals", "shared-device-signals":
		return normalizeDeviceSignals(input, sensorID)
	default:
		return nil, stats, fmt.Errorf("unsupported ingest source kind %q", source.Kind)
	}
	events := []normalized.Event{}
	decoder := json.NewDecoder(&output)
	for {
		var event normalized.Event
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return nil, stats, err
		}
		events = append(events, event)
	}
	return events, stats, nil
}

func normalizeDeviceSignals(input []byte, sensorID string) ([]normalized.Event, normalizedStats, error) {
	stats := normalizedStats{ByType: map[string]int{}}
	events := []normalized.Event{}
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		stats.Read++
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			stats.Malformed++
			continue
		}
		if event.SchemaVersion != "v1" || event.EventID == "" || event.Type != "device" || event.Timestamp == "" || event.Subject == nil {
			stats.Skipped++
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
			stats.Skipped++
			continue
		}
		if event.Observer == nil {
			event.Observer = map[string]any{}
		}
		event.Observer["sensor_id"] = sensorID
		events = append(events, event)
		stats.Emitted++
		stats.ByType[event.Type]++
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, err
	}
	return events, stats, nil
}

// A source keeps its canonical path in the durable checkpoint even while its
// retained, uncompressed .1 archive is drained. Only an exact file identity
// match may supply old bytes; unrelated archives must never be replayed.
type sourceChunk struct {
	data, header       []byte
	fileID             string
	start, end         int64
	truncated, archive bool
}

func readCompleteLines(path string, checkpoint ingest.Checkpoint, found bool, maxBytes int64) ([]byte, string, int64, int64, bool, error) {
	read, err := readSourceChunk(path, checkpoint, found, maxBytes, false)
	return read.data, read.fileID, read.start, read.end, read.truncated, err
}

func readSourceChunk(path string, checkpoint ingest.Checkpoint, found bool, maxBytes int64, withHeader bool) (sourceChunk, error) {
	current, openErr := os.Open(path)
	if openErr != nil && !os.IsNotExist(openErr) {
		return sourceChunk{}, openErr
	}
	var currentInfo os.FileInfo
	if current != nil {
		defer current.Close()
		var err error
		currentInfo, err = current.Stat()
		if err != nil {
			return sourceChunk{}, err
		}
	}
	if found && checkpoint.FileID != "" && (currentInfo == nil || fileIdentity(path, currentInfo) != checkpoint.FileID) {
		archivePath := path + ".1"
		info, err := os.Lstat(archivePath)
		if err != nil && !os.IsNotExist(err) {
			return sourceChunk{}, err
		}
		if err == nil && info.Mode().IsRegular() && fileIdentity(path, info) == checkpoint.FileID {
			archive, err := os.Open(archivePath)
			if err != nil {
				return sourceChunk{}, err
			}
			defer archive.Close()
			info, err = archive.Stat()
			if err != nil {
				return sourceChunk{}, err
			}
			if fileIdentity(path, info) == checkpoint.FileID && info.Size() > checkpoint.Offset {
				read, err := readFileChunk(archive, path, info, checkpoint, true, maxBytes, withHeader)
				read.archive = true
				// An incomplete archive tail may still be completed by the producer.
				// Leave the checkpoint in place instead of silently dropping that tail.
				if err == nil && len(read.data) == 0 {
					return read, fmt.Errorf("rotated source has an incomplete record pending")
				}
				return read, err
			}
		}
	}
	if current == nil {
		return sourceChunk{}, openErr
	}
	return readFileChunk(current, path, currentInfo, checkpoint, found, maxBytes, withHeader)
}

func readFileChunk(file *os.File, path string, info os.FileInfo, checkpoint ingest.Checkpoint, found bool, maxBytes int64, withHeader bool) (sourceChunk, error) {
	read := sourceChunk{fileID: fileIdentity(path, info), start: checkpoint.Offset}
	if found && ((checkpoint.FileID != "" && checkpoint.FileID != read.fileID) || read.start > info.Size()) {
		read.start, read.truncated = 0, true
	}
	if !found {
		read.start = 0
	}
	read.end = read.start
	if read.start < 0 || maxBytes <= 0 {
		return read, fmt.Errorf("invalid ingest offset or batch size")
	}
	remaining := info.Size() - read.start
	if remaining <= 0 {
		return read, nil
	}
	if remaining > maxBytes {
		remaining = maxBytes
	}
	data := make([]byte, remaining)
	n, err := file.ReadAt(data, read.start)
	if err != nil && err != io.EOF {
		return read, err
	}
	data = data[:n]
	lastNewline := bytes.LastIndexByte(data, '\n')
	if lastNewline < 0 {
		return read, nil
	}
	read.data = data[:lastNewline+1]
	read.end = read.start + int64(len(read.data))
	if withHeader && read.start > 0 {
		read.header, err = zeekHeader(file)
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// Header and records come from the same open descriptor, so a rename cannot
// pair an old batch with the replacement file's field layout.
func zeekHeader(file *os.File) ([]byte, error) {
	data := make([]byte, 128<<10)
	n, err := file.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	lines := []string{}
	for _, line := range strings.Split(string(data[:n]), "\n") {
		if strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
		if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
			break
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func fileIdentity(path string, info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%s:%d:%d", filepath.Clean(path), uint64(stat.Dev), uint64(stat.Ino))
	}
	return fmt.Sprintf("%s:%d", filepath.Clean(path), info.ModTime().UnixNano())
}

func stableID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:24]
}
func latestTimestamp(events []normalized.Event) string {
	result := ""
	for _, event := range events {
		if event.Timestamp > result {
			result = event.Timestamp
		}
	}
	return result
}
func sourceLag(path, fileID string, offset int64) int64 {
	current, err := os.Stat(path)
	if err == nil && (fileID == "" || fileIdentity(path, current) == fileID) {
		if current.Size() > offset {
			return current.Size() - offset
		}
		return 0
	}
	var lag int64
	// The replacement is entirely pending while the checkpoint still names
	// the archive. Do not subtract an old file's offset from its size.
	if err == nil {
		lag = current.Size()
	}
	archive, err := os.Stat(path + ".1")
	if err == nil && fileIdentity(path, archive) == fileID && archive.Size() > offset {
		lag += archive.Size() - offset
	}
	return lag
}

func severity(stats normalizedStats, truncated bool) string {
	if truncated || stats.Malformed > 0 {
		return "warning"
	}
	return "info"
}
func summary(stats normalizedStats, truncated bool) string {
	if truncated {
		return "source file rotated or truncated; ingestion resumed from the beginning"
	}
	if stats.Malformed > 0 {
		return "realtime batch committed with malformed records isolated"
	}
	return "realtime batch committed"
}
