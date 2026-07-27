package shadow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

type Options struct {
	EVEPath       string
	StatePath     string
	OutDir        string
	SensorID      string
	Window        time.Duration
	ListMinLevel  string
	ListLimit     int
	Retention     time.Duration
	StorageMode   string
	PostgresDSN   string
	ClickHouseDSN string
}

type State struct {
	EVEPath   string `json:"eve_path"`
	Offset    int64  `json:"offset"`
	UpdatedAt string `json:"updated_at"`
}

type RunSummary struct {
	StartedAt      string         `json:"started_at"`
	FinishedAt     string         `json:"finished_at"`
	EVEPath        string         `json:"eve_path"`
	RunDir         string         `json:"run_dir"`
	PreviousOffset int64          `json:"previous_offset"`
	NewOffset      int64          `json:"new_offset"`
	Truncated      bool           `json:"truncated"`
	Files          map[string]any `json:"files"`
	Normalized     suricata.Stats `json:"normalized"`
	EvidenceStats  evidence.Stats `json:"evidence_stats"`
	EvidenceCount  int            `json:"evidence_count"`
	RiskCount      int            `json:"risk_count"`
	RiskListCount  int            `json:"risk_list_count"`
	StorageMode    string         `json:"storage_mode"`
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
		StartedAt:      started.Format(time.RFC3339Nano),
		FinishedAt:     finished.Format(time.RFC3339Nano),
		EVEPath:        opts.EVEPath,
		RunDir:         runDir,
		PreviousOffset: previousOffset,
		NewOffset:      stat.Size(),
		Truncated:      truncated,
		Files: map[string]any{
			"normalized":           normalizedPath,
			"evidence":             evidencePath,
			"risk_snapshots":       riskPath,
			"risk_list_suspicious": riskListPath,
			"run_summary":          summaryPath,
		},
		Normalized:    normalizedStats,
		EvidenceStats: evidenceResult.Stats,
		EvidenceCount: len(evidenceResult.Evidence),
		RiskCount:     len(riskResult.Snapshots),
		RiskListCount: len(riskListResult.Snapshots),
		StorageMode:   opts.StorageMode,
	}
	if err := writeJSONFile(summaryPath, summary); err != nil {
		return RunSummary{}, err
	}
	if err := writeStoreOutputs(opts, summary, evidenceResult, riskResult, normalizedPath); err != nil {
		return RunSummary{}, err
	}

	state = State{EVEPath: opts.EVEPath, Offset: stat.Size(), UpdatedAt: finished.Format(time.RFC3339Nano)}
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
		EvidenceCount: summary.EvidenceCount,
		RiskCount:     summary.RiskCount,
		RiskListCount: summary.RiskListCount,
		RawRef: map[string]any{
			"backend": "suricata",
			"source":  summary.EVEPath,
			"offset":  summary.NewOffset,
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
			"run_id":          run.RunID,
			"previous_offset": summary.PreviousOffset,
			"new_offset":      summary.NewOffset,
			"truncated":       summary.Truncated,
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
	return nil
}

func diagnosticSeverity(summary RunSummary) string {
	if summary.Truncated || summary.Normalized.Malformed > 0 || summary.Normalized.Skipped > 0 {
		return "warning"
	}
	return "info"
}

func diagnosticSummary(summary RunSummary) string {
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
