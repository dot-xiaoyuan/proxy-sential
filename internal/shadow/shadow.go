package shadow

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

type Options struct {
	EVEPath          string
	ZeekDHCPPath     string
	ZeekSoftwarePath string
	StatePath        string
	OutDir           string
	SensorID         string
	Window           time.Duration
	ListMinLevel     string
	ListLimit        int
	Retention        time.Duration
	StorageMode      string
	PostgresDSN      string
	ClickHouseDSN    string
}

type State struct {
	EVEPath            string `json:"eve_path"`
	Offset             int64  `json:"offset"`
	ZeekDHCPPath       string `json:"zeek_dhcp_path,omitempty"`
	ZeekDHCPOffset     int64  `json:"zeek_dhcp_offset,omitempty"`
	ZeekSoftwarePath   string `json:"zeek_software_path,omitempty"`
	ZeekSoftwareOffset int64  `json:"zeek_software_offset,omitempty"`
	UpdatedAt          string `json:"updated_at"`
}

type RunSummary struct {
	StartedAt              string         `json:"started_at"`
	FinishedAt             string         `json:"finished_at"`
	EVEPath                string         `json:"eve_path"`
	ZeekDHCPPath           string         `json:"zeek_dhcp_path,omitempty"`
	ZeekSoftwarePath       string         `json:"zeek_software_path,omitempty"`
	ZeekStatus             string         `json:"zeek_status,omitempty"`
	ZeekReason             string         `json:"zeek_reason,omitempty"`
	RunDir                 string         `json:"run_dir"`
	PreviousOffset         int64          `json:"previous_offset"`
	NewOffset              int64          `json:"new_offset"`
	ZeekPrevOffset         int64          `json:"zeek_previous_offset,omitempty"`
	ZeekNewOffset          int64          `json:"zeek_new_offset,omitempty"`
	ZeekSoftwarePrevOffset int64          `json:"zeek_software_previous_offset,omitempty"`
	ZeekSoftwareNewOffset  int64          `json:"zeek_software_new_offset,omitempty"`
	Truncated              bool           `json:"truncated"`
	ZeekTruncated          bool           `json:"zeek_truncated,omitempty"`
	ZeekSoftwareTruncated  bool           `json:"zeek_software_truncated,omitempty"`
	Files                  map[string]any `json:"files"`
	Normalized             suricata.Stats `json:"normalized"`
	ZeekNormalized         zeek.Stats     `json:"zeek_normalized,omitempty"`
	EvidenceStats          evidence.Stats `json:"evidence_stats"`
	EvidenceCount          int            `json:"evidence_count"`
	RiskCount              int            `json:"risk_count"`
	RiskListCount          int            `json:"risk_list_count"`
	StorageMode            string         `json:"storage_mode"`
}

type zeekAppendResult struct {
	PreviousOffset int64
	NewOffset      int64
	Truncated      bool
	Stats          zeek.Stats
	Status         string
	Reason         string
}

func Run(opts Options) (RunSummary, error) {
	opts = withDefaults(opts)
	if opts.EVEPath == "" {
		return RunSummary{}, fmt.Errorf("--eve is required")
	}
	if opts.StatePath == "" {
		return RunSummary{}, fmt.Errorf("--state is required")
	}
	if opts.OutDir == "" {
		return RunSummary{}, fmt.Errorf("--out-dir is required")
	}

	started := time.Now()
	runDir, err := makeRunDir(opts.OutDir, started)
	if err != nil {
		return RunSummary{}, err
	}

	state, err := readState(opts.StatePath)
	if err != nil {
		return RunSummary{}, err
	}
	file, err := os.Open(opts.EVEPath)
	if err != nil {
		return RunSummary{}, fmt.Errorf("open eve: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return RunSummary{}, fmt.Errorf("stat eve: %w", err)
	}
	previousOffset := state.Offset
	if state.EVEPath != "" && state.EVEPath != opts.EVEPath {
		previousOffset = 0
	}
	truncated := false
	if previousOffset > stat.Size() {
		previousOffset = 0
		truncated = true
	}

	normalizedPath := filepath.Join(runDir, "normalized.jsonl")
	evidencePath := filepath.Join(runDir, "evidence.json")
	riskPath := filepath.Join(runDir, "risk-snapshots.json")
	riskListPath := filepath.Join(runDir, "risk-list-suspicious.json")
	summaryPath := filepath.Join(runDir, "run-summary.json")

	normalizedStats, err := writeNormalized(file, previousOffset, stat.Size(), normalizedPath, opts.SensorID)
	if err != nil {
		return RunSummary{}, err
	}
	zeekDHCPResult, err := appendZeekLog(opts.ZeekDHCPPath, state.ZeekDHCPPath, state.ZeekDHCPOffset, normalizedPath, opts.SensorID, "dhcp")
	if err != nil {
		return RunSummary{}, err
	}
	zeekSoftwareResult, err := appendZeekLog(opts.ZeekSoftwarePath, state.ZeekSoftwarePath, state.ZeekSoftwareOffset, normalizedPath, opts.SensorID, "software")
	if err != nil {
		return RunSummary{}, err
	}
	zeekStats := mergeZeekStats(zeekDHCPResult.Stats, zeekSoftwareResult.Stats)
	normalizedStats = mergeStats(normalizedStats, zeekStats)
	zeekStatus, zeekReason := aggregateZeekStatus(zeekDHCPResult, zeekSoftwareResult)

	evidenceResult, err := evidence.AnalyzeFiles(normalizedPath, evidencePath, evidence.Options{Window: opts.Window})
	if err != nil {
		return RunSummary{}, err
	}
	riskResult, err := risk.BatchFile(evidencePath, riskPath)
	if err != nil {
		return RunSummary{}, err
	}
	riskListResult, err := risk.ListFile(riskPath, riskListPath, risk.ListOptions{MinLevel: opts.ListMinLevel, Limit: opts.ListLimit})
	if err != nil {
		return RunSummary{}, err
	}

	finished := time.Now()
	summary := RunSummary{
		StartedAt:              started.Format(time.RFC3339Nano),
		FinishedAt:             finished.Format(time.RFC3339Nano),
		EVEPath:                opts.EVEPath,
		ZeekDHCPPath:           opts.ZeekDHCPPath,
		ZeekSoftwarePath:       opts.ZeekSoftwarePath,
		ZeekStatus:             zeekStatus,
		ZeekReason:             zeekReason,
		RunDir:                 runDir,
		PreviousOffset:         previousOffset,
		NewOffset:              stat.Size(),
		ZeekPrevOffset:         zeekDHCPResult.PreviousOffset,
		ZeekNewOffset:          zeekDHCPResult.NewOffset,
		ZeekSoftwarePrevOffset: zeekSoftwareResult.PreviousOffset,
		ZeekSoftwareNewOffset:  zeekSoftwareResult.NewOffset,
		Truncated:              truncated,
		ZeekTruncated:          zeekDHCPResult.Truncated,
		ZeekSoftwareTruncated:  zeekSoftwareResult.Truncated,
		Files: map[string]any{
			"normalized":           normalizedPath,
			"evidence":             evidencePath,
			"risk_snapshots":       riskPath,
			"risk_list_suspicious": riskListPath,
			"run_summary":          summaryPath,
		},
		Normalized:     normalizedStats,
		ZeekNormalized: zeekStats,
		EvidenceStats:  evidenceResult.Stats,
		EvidenceCount:  len(evidenceResult.Evidence),
		RiskCount:      len(riskResult.Snapshots),
		RiskListCount:  len(riskListResult.Snapshots),
		StorageMode:    opts.StorageMode,
	}
	if err := writeJSONFile(summaryPath, summary); err != nil {
		return RunSummary{}, err
	}
	if err := writeStoreOutputs(opts, summary, evidenceResult, riskResult, normalizedPath); err != nil {
		return RunSummary{}, err
	}

	state = State{
		EVEPath:            opts.EVEPath,
		Offset:             stat.Size(),
		ZeekDHCPPath:       opts.ZeekDHCPPath,
		ZeekDHCPOffset:     zeekDHCPResult.NewOffset,
		ZeekSoftwarePath:   opts.ZeekSoftwarePath,
		ZeekSoftwareOffset: zeekSoftwareResult.NewOffset,
		UpdatedAt:          finished.Format(time.RFC3339Nano),
	}
	if err := writeJSONFile(opts.StatePath, state); err != nil {
		return RunSummary{}, err
	}
	if err := cleanupRuns(opts.OutDir, opts.Retention, finished); err != nil {
		return RunSummary{}, err
	}

	return summary, nil
}

func withDefaults(opts Options) Options {
	if opts.Window == 0 {
		opts.Window = 10 * time.Minute
	}
	if opts.ListMinLevel == "" {
		opts.ListMinLevel = "suspicious"
	}
	if opts.ListLimit == 0 {
		opts.ListLimit = 50
	}
	if opts.Retention == 0 {
		opts.Retention = 7 * 24 * time.Hour
	}
	if opts.StorageMode == "" {
		opts.StorageMode = "file"
	}
	return opts
}

func writeStoreOutputs(opts Options, summary RunSummary, evidenceResult evidence.Result, riskResult risk.BatchResult, normalizedPath string) error {
	mode := store.Mode(opts.StorageMode)
	if mode == "" || mode == store.ModeFile {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	writer, err := store.NewWriter(store.Options{
		Mode:          mode,
		SensorID:      opts.SensorID,
		CollectorKind: "suricata",
		PostgresDSN:   opts.PostgresDSN,
		ClickHouseDSN: opts.ClickHouseDSN,
	})
	if err != nil {
		return err
	}
	run := store.Run{
		RunID:          filepath.Base(summary.RunDir),
		StartedAt:      summary.StartedAt,
		FinishedAt:     summary.FinishedAt,
		SensorID:       opts.SensorID,
		PreviousOffset: summary.PreviousOffset,
		NewOffset:      summary.NewOffset,
		Truncated:      summary.Truncated,
		Normalized: store.NormalizedCounts{
			Read:      summary.Normalized.Read,
			Emitted:   summary.Normalized.Emitted,
			Skipped:   summary.Normalized.Skipped,
			Malformed: summary.Normalized.Malformed,
			ByType:    summary.Normalized.ByType,
		},
		ZeekNormalized: store.NormalizedCounts{
			Read:      summary.ZeekNormalized.Read,
			Emitted:   summary.ZeekNormalized.Emitted,
			Skipped:   summary.ZeekNormalized.Skipped,
			Malformed: summary.ZeekNormalized.Malformed,
			ByType:    summary.ZeekNormalized.ByType,
		},
		ZeekStatus:             summary.ZeekStatus,
		ZeekReason:             summary.ZeekReason,
		ZeekPrevOffset:         summary.ZeekPrevOffset,
		ZeekNewOffset:          summary.ZeekNewOffset,
		ZeekTruncated:          summary.ZeekTruncated,
		ZeekSoftwarePrevOffset: summary.ZeekSoftwarePrevOffset,
		ZeekSoftwareNewOffset:  summary.ZeekSoftwareNewOffset,
		ZeekSoftwareTruncated:  summary.ZeekSoftwareTruncated,
		EvidenceCount:          summary.EvidenceCount,
		RiskCount:              summary.RiskCount,
		RiskListCount:          summary.RiskListCount,
		RawRef: map[string]any{
			"backend":            "suricata",
			"source":             summary.EVEPath,
			"offset":             summary.NewOffset,
			"zeek_dhcp_path":     summary.ZeekDHCPPath,
			"zeek_software_path": summary.ZeekSoftwarePath,
		},
	}
	diagnostic := ingest.Diagnostic{
		SchemaVersion: "v1",
		DiagnosticID:  "diag-" + run.RunID,
		Timestamp:     summary.FinishedAt,
		SensorID:      opts.SensorID,
		Collector:     ingest.Collector{Kind: "suricata"},
		Stage:         "normalize",
		Type:          "stats",
		Severity:      diagnosticSeverity(summary),
		Summary:       diagnosticSummary(summary),
		Counters: map[string]int{
			"read":      summary.Normalized.Read,
			"emitted":   summary.Normalized.Emitted,
			"skipped":   summary.Normalized.Skipped,
			"malformed": summary.Normalized.Malformed,
		},
		ByType: summary.Normalized.ByType,
		RawRef: run.RawRef,
		Details: map[string]any{
			"run_id":                        run.RunID,
			"previous_offset":               summary.PreviousOffset,
			"new_offset":                    summary.NewOffset,
			"truncated":                     summary.Truncated,
			"zeek_dhcp_path":                summary.ZeekDHCPPath,
			"zeek_previous_offset":          summary.ZeekPrevOffset,
			"zeek_new_offset":               summary.ZeekNewOffset,
			"zeek_truncated":                summary.ZeekTruncated,
			"zeek_status":                   summary.ZeekStatus,
			"zeek_reason":                   summary.ZeekReason,
			"zeek_normalized":               summary.ZeekNormalized,
			"zeek_software_path":            summary.ZeekSoftwarePath,
			"zeek_software_previous_offset": summary.ZeekSoftwarePrevOffset,
			"zeek_software_new_offset":      summary.ZeekSoftwareNewOffset,
			"zeek_software_truncated":       summary.ZeekSoftwareTruncated,
		},
	}
	events, err := readNormalizedEventsFile(normalizedPath)
	if err != nil {
		return err
	}
	if err := writer.WriteCollectorRun(ctx, run); err != nil {
		return err
	}
	if err := writer.WriteNormalizedEvents(ctx, events); err != nil {
		return err
	}
	if err := writer.WriteIngestDiagnostics(ctx, []ingest.Diagnostic{diagnostic}); err != nil {
		return err
	}
	if err := writer.WriteEvidence(ctx, evidenceResult.Evidence); err != nil {
		return err
	}
	if err := writer.WriteRiskSnapshots(ctx, riskResult.Snapshots); err != nil {
		return err
	}
	if err := writer.WriteDeviceState(ctx, run, events, riskResult.Snapshots); err != nil {
		return err
	}
	return nil
}

func diagnosticSeverity(summary RunSummary) string {
	if summary.Truncated || summary.Normalized.Malformed > 0 || summary.Normalized.Skipped > 0 || summary.ZeekStatus == "unavailable" || summary.ZeekStatus == "log_truncated" || summary.ZeekSoftwareTruncated {
		return "warning"
	}
	return "info"
}

func diagnosticSummary(summary RunSummary) string {
	switch summary.ZeekStatus {
	case "unavailable":
		return "collector run completed while one or more zeek logs were unavailable"
	case "log_truncated":
		return "collector run completed after zeek log rotation"
	case "no_dhcp_events":
		return "collector run completed with no zeek device events"
	}
	if summary.Truncated {
		return "input log was truncated or rotated during the latest run"
	}
	if summary.Normalized.Malformed > 0 {
		return "latest run contains malformed input records"
	}
	if summary.Normalized.Skipped > 0 {
		return "latest run contains skipped input records"
	}
	return "collector and normalization pipeline are producing standard events"
}

func readNormalizedEventsFile(path string) ([]normalized.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	events := []normalized.Event{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func writeNormalized(file *os.File, offset int64, size int64, outputPath string, sensorID string) (suricata.Stats, error) {
	output, err := os.Create(outputPath)
	if err != nil {
		return suricata.Stats{}, fmt.Errorf("create normalized output: %w", err)
	}
	defer output.Close()

	length := size - offset
	if length < 0 {
		length = 0
	}
	section := io.NewSectionReader(file, offset, length)
	stats, err := suricata.Convert(section, output, suricata.Options{SensorID: sensorID})
	if err != nil {
		return stats, err
	}
	return stats, nil
}

func appendZeekLog(path string, statePath string, stateOffset int64, outputPath string, sensorID string, logName string) (zeekAppendResult, error) {
	result := zeekAppendResult{Stats: zeek.Stats{ByType: map[string]int{}}, Status: "not_configured", Reason: "zeek " + logName + " log path is not configured"}
	if path == "" {
		return result, nil
	}
	result.Status = "unavailable"
	result.Reason = "zeek " + logName + " log is not available"
	previousOffset := int64(0)
	if statePath == path {
		previousOffset = stateOffset
	}
	result.PreviousOffset = previousOffset
	result.NewOffset = previousOffset
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		result.Reason = "zeek " + logName + " log does not exist"
		return result, nil
	}
	if err != nil {
		result.Reason = "zeek " + logName + " log cannot be opened: " + err.Error()
		return result, nil
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		result.Reason = "zeek " + logName + " log cannot be inspected: " + err.Error()
		return result, nil
	}
	truncated := false
	if previousOffset > stat.Size() {
		previousOffset = 0
		truncated = true
	}
	result.PreviousOffset = previousOffset
	result.NewOffset = stat.Size()
	result.Truncated = truncated
	output, err := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return result, fmt.Errorf("open normalized output for zeek append: %w", err)
	}
	defer output.Close()

	length := stat.Size() - previousOffset
	if length < 0 {
		length = 0
	}
	section := io.NewSectionReader(file, previousOffset, length)
	var reader io.Reader = section
	if previousOffset > 0 {
		header, err := zeekHeader(file, previousOffset)
		if err != nil {
			return result, err
		}
		if len(header) > 0 {
			reader = io.MultiReader(bytes.NewReader(header), section)
		}
	}
	stats, err := zeek.Convert(reader, output, zeek.Options{SensorID: sensorID})
	result.Stats = stats
	if err != nil {
		return result, err
	}
	switch {
	case truncated:
		result.Status = "log_truncated"
		result.Reason = "zeek " + logName + " log was rotated or truncated; offset was reset"
	case stats.Emitted > 0:
		result.Status = "ok"
		result.Reason = "zeek " + logName + " log produced device events"
	case stat.Size() == 0 || stats.Read == 0:
		result.Status = "no_dhcp_events"
		result.Reason = "zeek " + logName + " log exists but has no new rows"
	default:
		result.Status = "no_dhcp_events"
		result.Reason = "zeek " + logName + " log was read but emitted no device events"
	}
	return result, nil
}

func zeekHeader(file *os.File, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	if limit > 1024*1024 {
		limit = 1024 * 1024
	}
	reader := io.NewSectionReader(file, 0, limit)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var header bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			break
		}
		header.WriteString(line)
		header.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read zeek header: %w", err)
	}
	return header.Bytes(), nil
}

func mergeStats(base suricata.Stats, extra zeek.Stats) suricata.Stats {
	base.Read += extra.Read
	base.Emitted += extra.Emitted
	base.Skipped += extra.Skipped
	base.Malformed += extra.Malformed
	if base.ByType == nil {
		base.ByType = map[string]int{}
	}
	for eventType, count := range extra.ByType {
		base.ByType[eventType] += count
	}
	return base
}

func mergeZeekStats(base zeek.Stats, extra zeek.Stats) zeek.Stats {
	base.Read += extra.Read
	base.Emitted += extra.Emitted
	base.Skipped += extra.Skipped
	base.Malformed += extra.Malformed
	if base.ByType == nil {
		base.ByType = map[string]int{}
	}
	for eventType, count := range extra.ByType {
		base.ByType[eventType] += count
	}
	return base
}

func aggregateZeekStatus(results ...zeekAppendResult) (string, string) {
	configured := false
	reasons := []string{}
	statusRank := map[string]int{
		"not_configured": 0,
		"no_dhcp_events": 1,
		"unavailable":    2,
		"log_truncated":  3,
		"ok":             4,
	}
	status := "not_configured"
	for _, result := range results {
		if result.Status != "not_configured" {
			configured = true
		}
		if result.Reason != "" && result.Status != "not_configured" {
			reasons = append(reasons, result.Reason)
		}
		if statusRank[result.Status] > statusRank[status] {
			status = result.Status
		}
	}
	if !configured {
		return "not_configured", "zeek log paths are not configured"
	}
	if len(reasons) == 0 {
		return status, "zeek logs are configured"
	}
	return status, strings.Join(reasons, "; ")
}

func readState(path string) (State, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("open state: %w", err)
	}
	defer file.Close()

	var state State
	if err := json.NewDecoder(file).Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}
	return state, nil
}

func makeRunDir(outDir string, now time.Time) (string, error) {
	runsDir := filepath.Join(outDir, "runs")
	if err := os.MkdirAll(runsDir, 0755); err != nil {
		return "", fmt.Errorf("create runs directory: %w", err)
	}
	base := now.Format("20060102-150405")
	for i := 0; i < 100; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s-%02d", base, i+1)
		}
		runDir := filepath.Join(runsDir, name)
		err := os.Mkdir(runDir, 0755)
		if err == nil {
			return runDir, nil
		}
		if os.IsExist(err) {
			continue
		}
		return "", fmt.Errorf("create run directory: %w", err)
	}
	return "", fmt.Errorf("cannot allocate unique run directory under %s", runsDir)
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create json file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write json file: %w", err)
	}
	return nil
}

func cleanupRuns(outDir string, retention time.Duration, now time.Time) error {
	if retention <= 0 {
		return nil
	}
	runsDir := filepath.Join(outDir, "runs")
	entries, err := os.ReadDir(runsDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read runs directory: %w", err)
	}
	cutoff := now.Add(-retention)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat run directory: %w", err)
		}
		if info.ModTime().Before(cutoff) {
			if err := os.RemoveAll(filepath.Join(runsDir, entry.Name())); err != nil {
				return fmt.Errorf("remove expired run directory: %w", err)
			}
		}
	}
	return nil
}
