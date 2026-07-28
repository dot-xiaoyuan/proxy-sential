package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

type FileOptions struct {
	ShadowDir     string
	SensorID      string
	CollectorKind string
	CollectorVer  string
	InterfaceName string
	StorageMode   string
}

type FileStore struct {
	shadowDir     string
	sensorID      string
	collectorKind string
	collectorVer  string
	interfaceName string
	storageMode   string
}

type fileRun struct {
	Run
	Dir     string
	Started time.Time
}

type runSummary struct {
	StartedAt      string         `json:"started_at"`
	FinishedAt     string         `json:"finished_at"`
	EVEPath        string         `json:"eve_path"`
	PreviousOffset int64          `json:"previous_offset"`
	NewOffset      int64          `json:"new_offset"`
	Truncated      bool           `json:"truncated"`
	Files          map[string]any `json:"files"`
	Normalized     NormalizedCounts
	EvidenceCount  int `json:"evidence_count"`
	RiskCount      int `json:"risk_count"`
	RiskListCount  int `json:"risk_list_count"`
}

func NewFileStore(opts FileOptions) *FileStore {
	shadowDir := opts.ShadowDir
	if shadowDir == "" {
		shadowDir = "data/shadow"
	}
	sensorID := opts.SensorID
	if sensorID == "" {
		sensorID = "office-30"
	}
	collectorKind := opts.CollectorKind
	if collectorKind == "" {
		collectorKind = "suricata"
	}
	interfaceName := opts.InterfaceName
	if interfaceName == "" {
		interfaceName = "ens1f1"
	}
	storageMode := opts.StorageMode
	if storageMode == "" {
		storageMode = string(ModeFile)
	}
	return &FileStore{
		shadowDir:     shadowDir,
		sensorID:      sensorID,
		collectorKind: collectorKind,
		collectorVer:  opts.CollectorVer,
		interfaceName: interfaceName,
		storageMode:   storageMode,
	}
}

func (s *FileStore) Overview(ctx context.Context) (Overview, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return Overview{}, err
	}
	if !ok {
		return Overview{
			LevelCounts: map[string]int{"normal": 0, "suspicious": 0, "high": 0, "confirmed": 0},
			Throughput:  map[string]int{"events": 0, "evidence": 0, "risks": 0},
			TopEvidence: []ingest.EventTypeCount{},
			LatestRun:   Run{SensorID: s.sensorID, Normalized: NormalizedCounts{ByType: map[string]int{}}},
		}, nil
	}
	batch, err := readRiskBatch(filepath.Join(latest.Dir, "risk-snapshots.json"))
	if err != nil {
		return Overview{}, err
	}
	evidenceResult, err := readEvidence(filepath.Join(latest.Dir, "evidence.json"))
	if err != nil {
		return Overview{}, err
	}
	counts := levelCounts(batch.Snapshots)
	return Overview{
		LevelCounts:    counts,
		PendingReviews: counts["high"] + counts["confirmed"],
		LatestRun:      latest.Run,
		Throughput: map[string]int{
			"events":   latest.Normalized.Emitted,
			"evidence": latest.EvidenceCount,
			"risks":    latest.RiskCount,
		},
		TopEvidence: topEvidence(evidenceResult.Evidence),
	}, nil
}

func (s *FileStore) ListRisks(ctx context.Context, query Query) (RiskPage, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return RiskPage{}, err
	}
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	if !ok || (query.SensorID != "" && query.SensorID != s.sensorID) {
		return RiskPage{Items: []risk.Snapshot{}, Page: Page{Limit: limit, Total: 0}}, nil
	}
	batch, err := readRiskBatch(filepath.Join(latest.Dir, "risk-snapshots.json"))
	if err != nil {
		return RiskPage{}, err
	}
	items, err := filterRisks(batch.Snapshots, query)
	if err != nil {
		return RiskPage{}, err
	}
	total := len(items)
	cursor := query.Cursor
	if cursor > total {
		cursor = total
	}
	end := cursor + limit
	if end > total {
		end = total
	}
	var next *string
	if end < total {
		value := strconv.Itoa(end)
		next = &value
	}
	return RiskPage{Items: items[cursor:end], Page: Page{Limit: limit, NextCursor: next, Total: total}}, nil
}

func (s *FileStore) GetIPRisk(ctx context.Context, ip string) (risk.Snapshot, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return risk.Snapshot{}, err
	}
	if !ok {
		return normalRisk(ip), nil
	}
	batch, err := readRiskBatch(filepath.Join(latest.Dir, "risk-snapshots.json"))
	if err != nil {
		return risk.Snapshot{}, err
	}
	for _, snapshot := range batch.Snapshots {
		if snapshot.IP == ip {
			return snapshot, nil
		}
	}
	return normalRisk(ip), nil
}

func (s *FileStore) GetIPEvidence(ctx context.Context, ip string) ([]evidence.Evidence, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []evidence.Evidence{}, nil
	}
	result, err := readEvidence(filepath.Join(latest.Dir, "evidence.json"))
	if err != nil {
		return nil, err
	}
	items := make([]evidence.Evidence, 0)
	for _, item := range result.Evidence {
		if item.IP == ip {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt == items[j].CreatedAt {
			return items[i].EvidenceID < items[j].EvidenceID
		}
		return items[i].CreatedAt > items[j].CreatedAt
	})
	return items, nil
}

func (s *FileStore) GetIPActivity(ctx context.Context, ip string, limit int) (ActivityProfile, error) {
	events, err := s.ListEventSamples(ctx, Query{Q: ip, Limit: defaultActivityEventLimit})
	if err != nil {
		return ActivityProfile{}, err
	}
	return BuildActivityProfile(ip, events, limit), nil
}

func (s *FileStore) GetActivityOverview(ctx context.Context, query ActivityQuery) (ActivityOverview, error) {
	window, _, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return ActivityOverview{}, err
	}
	sensorID := query.SensorID
	if sensorID == "" {
		sensorID = s.sensorID
	}
	if sensorID != s.sensorID {
		return BuildActivityOverview(sensorID, window, []normalized.Event{}, map[string]risk.Snapshot{}), nil
	}
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return ActivityOverview{}, err
	}
	if !ok {
		return BuildActivityOverview(sensorID, window, []normalized.Event{}, map[string]risk.Snapshot{}), nil
	}
	limit := query.Limit
	if limit <= 0 {
		limit = defaultActivityOverviewEventLimit
	}
	events, err := readNormalizedEvents(ctx, filepath.Join(latest.Dir, "normalized.jsonl"), Query{SensorID: sensorID, Limit: limit})
	if err != nil {
		return ActivityOverview{}, err
	}
	batch, err := readRiskBatch(filepath.Join(latest.Dir, "risk-snapshots.json"))
	if err != nil {
		return ActivityOverview{}, err
	}
	return BuildActivityOverview(sensorID, window, events, riskSnapshotMap(batch.Snapshots)), nil
}

func (s *FileStore) ListEventSamples(ctx context.Context, query Query) ([]normalized.Event, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []normalized.Event{}, nil
	}
	return readNormalizedEvents(ctx, filepath.Join(latest.Dir, "normalized.jsonl"), query)
}

func (s *FileStore) ListEvents(ctx context.Context, query Query) (EventPage, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	events, err := s.ListEventSamples(ctx, Query{
		Level:       query.Level,
		Q:           query.Q,
		SensorID:    query.SensorID,
		From:        query.From,
		To:          query.To,
		Window:      query.Window,
		SrcIP:       query.SrcIP,
		DstIP:       query.DstIP,
		Domain:      query.Domain,
		UserAgent:   query.UserAgent,
		Fingerprint: query.Fingerprint,
		Port:        query.Port,
		Proto:       query.Proto,
		Limit:       -1,
	})
	if err != nil {
		return EventPage{}, err
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Timestamp != events[j].Timestamp {
			return events[i].Timestamp > events[j].Timestamp
		}
		return events[i].EventID > events[j].EventID
	})
	total := len(events)
	cursor := query.Cursor
	if cursor > total {
		cursor = total
	}
	end := cursor + limit
	if end > total {
		end = total
	}
	var next *string
	if end < total {
		value := strconv.Itoa(end)
		next = &value
	}
	return EventPage{Items: events[cursor:end], Page: Page{Limit: limit, NextCursor: next, Total: total}}, nil
}

func (s *FileStore) GetEvent(ctx context.Context, eventID string) (normalized.Event, bool, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil || !ok {
		return normalized.Event{}, false, err
	}
	events, err := readNormalizedEvents(ctx, filepath.Join(latest.Dir, "normalized.jsonl"), Query{Q: eventID, Limit: 1})
	if err != nil {
		return normalized.Event{}, false, err
	}
	for _, event := range events {
		if event.EventID == eventID {
			return event, true, nil
		}
	}
	return normalized.Event{}, false, nil
}

func (s *FileStore) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	runs, err := s.runs(ctx)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(runs) > limit {
		runs = runs[:limit]
	}
	result := make([]Run, 0, len(runs))
	for _, run := range runs {
		result = append(result, run.Run)
	}
	return result, nil
}

func (s *FileStore) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	runs, err := s.runs(ctx)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(runs) > limit {
		runs = runs[:limit]
	}
	logs := make([]AuditLog, 0, len(runs))
	for _, run := range runs {
		logs = append(logs, AuditLog{
			AuditID:   "audit-shadow-" + run.RunID,
			Actor:     "system",
			Action:    "collector.run",
			Target:    run.RunID,
			Outcome:   fmt.Sprintf("risk_list_count=%d", run.RiskListCount),
			CreatedAt: run.FinishedAt,
		})
	}
	return logs, nil
}

func (s *FileStore) IngestStatus(ctx context.Context) (ingest.Status, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return ingest.Status{}, err
	}
	status := ingest.Status{
		SensorID:    s.sensorID,
		Collector:   s.collector(),
		StorageMode: s.storageMode,
		Healthy:     ok,
		Severity:    "warning",
		Summary:     "no collector runs found",
		LastCounters: map[string]int{
			"read": 0, "emitted": 0, "skipped": 0, "malformed": 0,
		},
		LastEventTypeDist: map[string]int{},
	}
	if !ok {
		return status, nil
	}
	status.LatestRunID = latest.RunID
	status.LatestRunAt = latest.FinishedAt
	status.LastCounters = map[string]int{
		"read":      latest.Normalized.Read,
		"emitted":   latest.Normalized.Emitted,
		"skipped":   latest.Normalized.Skipped,
		"malformed": latest.Normalized.Malformed,
	}
	status.LastEventTypeDist = latest.Normalized.ByType
	status.Healthy = latest.Normalized.Malformed == 0 && !latest.Truncated
	status.Severity = "info"
	status.Summary = "collector and normalization pipeline are producing standard events"
	if latest.Truncated {
		status.Severity = "warning"
		status.Summary = "input log was truncated or rotated during the latest run"
	} else if latest.Normalized.Malformed > 0 {
		status.Severity = "warning"
		status.Summary = "latest run contains malformed input records"
	}
	return status, nil
}

func (s *FileStore) ListIngestDiagnostics(ctx context.Context, query Query) ([]ingest.Diagnostic, error) {
	runs, err := s.runs(ctx)
	if err != nil {
		return nil, err
	}
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	diagnostics := make([]ingest.Diagnostic, 0, len(runs))
	for _, run := range runs {
		diagnostics = append(diagnostics, s.diagnosticForRun(run))
		if len(diagnostics) >= limit {
			break
		}
	}
	if diagnostics == nil {
		return []ingest.Diagnostic{}, nil
	}
	return diagnostics, nil
}

func (s *FileStore) ListIngestEventTypes(ctx context.Context) ([]ingest.EventTypeCount, error) {
	latest, ok, err := s.latestRun(ctx)
	if err != nil || !ok {
		return []ingest.EventTypeCount{}, err
	}
	result := make([]ingest.EventTypeCount, 0, len(latest.Normalized.ByType))
	for eventType, count := range latest.Normalized.ByType {
		result = append(result, ingest.EventTypeCount{Type: eventType, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Type < result[j].Type
	})
	return result, nil
}

func (s *FileStore) ListIngestErrors(ctx context.Context, limit int) ([]ingest.Diagnostic, error) {
	if limit == 0 {
		limit = 50
	}
	items, err := s.ListIngestDiagnostics(ctx, Query{Limit: limit})
	if err != nil {
		return nil, err
	}
	errorsOnly := make([]ingest.Diagnostic, 0)
	for _, item := range items {
		if item.Severity == "warning" || item.Severity == "error" {
			errorsOnly = append(errorsOnly, item)
		}
	}
	if errorsOnly == nil {
		return []ingest.Diagnostic{}, nil
	}
	return errorsOnly, nil
}

func (s *FileStore) latestRun(ctx context.Context) (fileRun, bool, error) {
	runs, err := s.runs(ctx)
	if err != nil {
		return fileRun{}, false, err
	}
	if len(runs) == 0 {
		return fileRun{}, false, nil
	}
	return runs[0], true, nil
}

func (s *FileStore) runs(ctx context.Context) ([]fileRun, error) {
	runsDir := filepath.Join(s.shadowDir, "runs")
	entries, err := os.ReadDir(runsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return []fileRun{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runs directory: %w", err)
	}
	runs := make([]fileRun, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.IsDir() {
			continue
		}
		runDir := filepath.Join(runsDir, entry.Name())
		summary, err := readRunSummary(filepath.Join(runDir, "run-summary.json"))
		if err != nil {
			continue
		}
		started, _ := time.Parse(time.RFC3339Nano, summary.StartedAt)
		byType := map[string]int{}
		for k, v := range summary.Normalized.ByType {
			byType[k] = v
		}
		runs = append(runs, fileRun{
			Run: Run{
				RunID:          entry.Name(),
				StartedAt:      summary.StartedAt,
				FinishedAt:     summary.FinishedAt,
				SensorID:       s.sensorID,
				PreviousOffset: summary.PreviousOffset,
				NewOffset:      summary.NewOffset,
				Truncated:      summary.Truncated,
				Normalized: NormalizedCounts{
					Read:      summary.Normalized.Read,
					Emitted:   summary.Normalized.Emitted,
					Skipped:   summary.Normalized.Skipped,
					Malformed: summary.Normalized.Malformed,
					ByType:    byType,
				},
				EvidenceCount: summary.EvidenceCount,
				RiskCount:     summary.RiskCount,
				RiskListCount: summary.RiskListCount,
				RawRef: map[string]any{
					"backend": "suricata",
					"source":  summary.EVEPath,
					"offset":  summary.NewOffset,
				},
			},
			Dir:     runDir,
			Started: started,
		})
	}
	sort.Slice(runs, func(i, j int) bool {
		if !runs[i].Started.Equal(runs[j].Started) {
			return runs[i].Started.After(runs[j].Started)
		}
		return runs[i].RunID > runs[j].RunID
	})
	return runs, nil
}

func (s *FileStore) collector() ingest.Collector {
	return ingest.Collector{Kind: s.collectorKind, Version: s.collectorVer, Interface: s.interfaceName}
}

func (s *FileStore) diagnosticForRun(run fileRun) ingest.Diagnostic {
	severity := "info"
	summary := "collector run completed and emitted normalized events"
	if run.Truncated || run.Normalized.Skipped > 0 {
		severity = "warning"
		summary = "collector run completed with skipped or rotated input"
	}
	if run.Normalized.Malformed > 0 {
		severity = "warning"
		summary = "collector run completed with malformed input records"
	}
	return ingest.Diagnostic{
		SchemaVersion: "v1",
		DiagnosticID:  diagnosticID(run.RunID),
		Timestamp:     run.FinishedAt,
		SensorID:      s.sensorID,
		Collector:     s.collector(),
		Stage:         "normalize",
		Type:          "stats",
		Severity:      severity,
		Summary:       summary,
		Counters: map[string]int{
			"read":      run.Normalized.Read,
			"emitted":   run.Normalized.Emitted,
			"skipped":   run.Normalized.Skipped,
			"malformed": run.Normalized.Malformed,
		},
		ByType: run.Normalized.ByType,
		RawRef: run.RawRef,
		Details: map[string]any{
			"run_id":          run.RunID,
			"previous_offset": run.PreviousOffset,
			"new_offset":      run.NewOffset,
			"truncated":       run.Truncated,
		},
	}
}

func diagnosticID(runID string) string {
	sum := sha256.Sum256([]byte("ingest-diagnostic|" + runID))
	return "diag-" + hex.EncodeToString(sum[:])[:20]
}

func readRunSummary(path string) (runSummary, error) {
	var summary runSummary
	if err := readJSONFile(path, &summary); err != nil {
		return runSummary{}, err
	}
	return summary, nil
}

func readRiskBatch(path string) (risk.BatchResult, error) {
	var batch risk.BatchResult
	if err := readJSONFile(path, &batch); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return risk.BatchResult{Snapshots: []risk.Snapshot{}}, nil
		}
		return risk.BatchResult{}, err
	}
	if batch.Snapshots == nil {
		batch.Snapshots = []risk.Snapshot{}
	}
	return batch, nil
}

func readEvidence(path string) (evidence.Result, error) {
	var result evidence.Result
	if err := readJSONFile(path, &result); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return evidence.Result{Evidence: []evidence.Evidence{}}, nil
		}
		return evidence.Result{}, err
	}
	if result.Evidence == nil {
		result.Evidence = []evidence.Evidence{}
	}
	return result, nil
}

func readJSONFile(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func filterRisks(snapshots []risk.Snapshot, query Query) ([]risk.Snapshot, error) {
	if query.Level != "" {
		if _, ok := levelRank(query.Level); !ok {
			return nil, fmt.Errorf("unknown level: %s", query.Level)
		}
	}
	q := strings.ToLower(query.Q)
	from, err := optionalTime(query.From)
	if err != nil {
		return nil, fmt.Errorf("bad from: %w", err)
	}
	to, err := optionalTime(query.To)
	if err != nil {
		return nil, fmt.Errorf("bad to: %w", err)
	}
	items := make([]risk.Snapshot, 0, len(snapshots))
	for _, item := range snapshots {
		if query.Level != "" && item.Level != query.Level {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.IP), q) && !strings.Contains(strings.ToLower(item.Summary), q) {
			continue
		}
		updatedAt, ok := parseTime(item.UpdatedAt)
		if !from.IsZero() && (!ok || updatedAt.Before(from)) {
			continue
		}
		if !to.IsZero() && (!ok || updatedAt.After(to)) {
			continue
		}
		items = append(items, item)
	}
	sortRisks(items)
	return items, nil
}

func sortRisks(items []risk.Snapshot) {
	sort.Slice(items, func(i, j int) bool {
		leftRank, _ := levelRank(items[i].Level)
		rightRank, _ := levelRank(items[j].Level)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		return items[i].IP < items[j].IP
	})
}

func readNormalizedEvents(ctx context.Context, path string, query Query) ([]normalized.Event, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []normalized.Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	from, err := optionalTime(query.From)
	if err != nil {
		return nil, fmt.Errorf("bad from: %w", err)
	}
	to, err := optionalTime(query.To)
	if err != nil {
		return nil, fmt.Errorf("bad to: %w", err)
	}
	if query.Window != "" && query.From == "" && query.To == "" {
		_, duration, err := NormalizeActivityWindow(query.Window)
		if err != nil {
			return nil, err
		}
		to = time.Now()
		from = to.Add(-duration)
	}
	events := make([]normalized.Event, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if !eventMatchesQuery(event, query, from, to) {
			continue
		}
		events = append(events, event)
		if limit > 0 && len(events) > limit {
			events = events[len(events)-limit:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func eventMatchesQuery(event normalized.Event, query Query, from time.Time, to time.Time) bool {
	if query.Q != "" {
		q := strings.ToLower(query.Q)
		if !strings.Contains(strings.ToLower(event.EventID), q) &&
			!strings.Contains(strings.ToLower(subjectIP(event)), q) &&
			!strings.Contains(strings.ToLower(stringFromMap(event.Flow, "dst_ip")), q) &&
			!strings.Contains(strings.ToLower(eventDomain(event)), q) {
			return false
		}
	}
	if query.Level != "" && event.Type != query.Level {
		return false
	}
	if query.SensorID != "" && stringFromMap(event.Observer, "sensor_id") != query.SensorID {
		return false
	}
	timestamp, ok := parseTime(event.Timestamp)
	if !from.IsZero() && (!ok || timestamp.Before(from)) {
		return false
	}
	if !to.IsZero() && (!ok || timestamp.After(to)) {
		return false
	}
	if query.SrcIP != "" && subjectIP(event) != query.SrcIP && stringFromMap(event.Flow, "src_ip") != query.SrcIP {
		return false
	}
	if query.DstIP != "" && stringFromMap(event.Flow, "dst_ip") != query.DstIP {
		return false
	}
	if query.Domain != "" && !strings.Contains(strings.ToLower(eventDomain(event)), strings.ToLower(query.Domain)) {
		return false
	}
	if query.UserAgent != "" && !strings.Contains(strings.ToLower(stringFromMap(event.Payload, "user_agent")), strings.ToLower(query.UserAgent)) {
		return false
	}
	if query.Fingerprint != "" {
		fingerprint, ok := normalizeFingerprintFilter(query.Fingerprint)
		if !ok || !strings.Contains(strings.ToLower(eventFingerprint(event)), strings.ToLower(fingerprint)) {
			return false
		}
	}
	if query.Port > 0 && intFromMap(event.Flow, "dst_port") != query.Port {
		return false
	}
	if query.Proto != "" && !strings.EqualFold(stringFromMap(event.Flow, "proto"), query.Proto) {
		return false
	}
	return true
}

func eventDomain(event normalized.Event) string {
	switch event.Type {
	case "dns":
		return stringFromMap(event.Payload, "query")
	case "http":
		return stringFromMap(event.Payload, "host")
	case "tls":
		return stringFromMap(event.Payload, "sni")
	default:
		return ""
	}
}

func eventFingerprint(event normalized.Event) string {
	return stringFromMap(event.Payload, "ja3") + " " + stringFromMap(event.Payload, "ja4")
}

func normalizeFingerprintFilter(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "ja3:") || strings.HasPrefix(lower, "ja4:") {
		trimmed = strings.TrimSpace(trimmed[4:])
	}
	return trimmed, trimmed != ""
}

func topEvidence(items []evidence.Evidence) []ingest.EventTypeCount {
	counts := map[string]int{}
	for _, item := range items {
		if item.Type != "" {
			counts[item.Type]++
		}
	}
	result := make([]ingest.EventTypeCount, 0, len(counts))
	for evidenceType, count := range counts {
		result = append(result, ingest.EventTypeCount{Type: evidenceType, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Type < result[j].Type
	})
	return result
}

func levelCounts(items []risk.Snapshot) map[string]int {
	counts := map[string]int{"normal": 0, "suspicious": 0, "high": 0, "confirmed": 0}
	for _, item := range items {
		if _, ok := counts[item.Level]; ok {
			counts[item.Level]++
		}
	}
	return counts
}

func normalRisk(ip string) risk.Snapshot {
	return risk.Snapshot{
		IP:                ip,
		Score:             0,
		Level:             "normal",
		Confidence:        0,
		Window:            "none",
		EvidenceIDs:       []string{},
		Summary:           "未发现该 IP 的有效风险证据",
		RecommendedAction: "record",
		UpdatedAt:         NowRFC3339(),
	}
}

func optionalTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	value, ok := parseTime(raw)
	if !ok {
		return time.Time{}, fmt.Errorf("must be RFC3339")
	}
	return value, nil
}

func parseTime(raw string) (time.Time, bool) {
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return value, true
}

func levelRank(level string) (int, bool) {
	switch level {
	case "normal":
		return 0, true
	case "suspicious":
		return 1, true
	case "high":
		return 2, true
	case "confirmed":
		return 3, true
	default:
		return 0, false
	}
}

func DecodePathIP(raw string) (string, error) {
	ip, err := url.PathUnescape(raw)
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", fmt.Errorf("ip is required")
	}
	return ip, nil
}
