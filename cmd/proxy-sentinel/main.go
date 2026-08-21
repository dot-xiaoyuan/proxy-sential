package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/controlplane"
	"proxy-sentinel/internal/evaluation"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/replay"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/shadow"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/validation"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return usageError()
	}

	switch args[0] {
	case "adapter":
		return runAdapter(args[1:])
	case "replay":
		return runReplay(args[1:])
	case "evidence":
		return runEvidence(args[1:])
	case "risk":
		return runRisk(args[1:])
	case "shadow":
		return runShadow(args[1:])
	case "control-plane":
		return runControlPlane(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "evaluate":
		return runEvaluate(args[1:])
	case "-h", "--help", "help":
		return usageError()
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func runAdapter(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing adapter name")
	}

	switch args[0] {
	case "suricata":
		return runSuricataAdapter(args[1:])
	case "zeek":
		return runZeekAdapter(args[1:])
	case "identity":
		return runIdentityAdapter(args[1:])
	default:
		return fmt.Errorf("unknown adapter: %s", args[0])
	}
}

func runSuricataAdapter(args []string) error {
	fs := flag.NewFlagSet("adapter suricata", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "Suricata EVE JSONL input path, or - for stdin")
	output := fs.String("output", "", "normalized JSONL output path, or - for stdout")
	sensorID := fs.String("sensor-id", "", "optional sensor identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	stats, err := suricata.ConvertFiles(*input, *output, suricata.Options{SensorID: *sensorID})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "suricata adapter: read=%d emitted=%d skipped=%d malformed=%d\n", stats.Read, stats.Emitted, stats.Skipped, stats.Malformed)
	return nil
}

func runZeekAdapter(args []string) error {
	fs := flag.NewFlagSet("adapter zeek", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "Zeek dhcp.log or software.log input path, or - for stdin")
	output := fs.String("output", "", "normalized JSONL output path, or - for stdout")
	sensorID := fs.String("sensor-id", "", "optional sensor identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	stats, err := zeek.ConvertFiles(*input, *output, zeek.Options{SensorID: *sensorID})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "zeek adapter: read=%d emitted=%d skipped=%d malformed=%d\n", stats.Read, stats.Emitted, stats.Skipped, stats.Malformed)
	return nil
}

func runIdentityAdapter(args []string) error {
	fs := flag.NewFlagSet("adapter identity", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "identity JSONL/CSV input path, or - for stdin")
	output := fs.String("output", "", "normalized JSONL output path, or - for stdout")
	sensorID := fs.String("sensor-id", "", "optional sensor identifier")
	source := fs.String("source", "", "identity source name, for example radius, portal, dot1x, dhcp, switch, ac")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	in, closeInput, err := openInput(*input)
	if err != nil {
		return err
	}
	defer closeInput()
	out, closeOutput, err := openOutput(*output)
	if err != nil {
		return err
	}
	defer closeOutput()
	stats, err := identity.Convert(in, out, identity.Options{SensorID: *sensorID, Source: *source})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "identity adapter: read=%d emitted=%d skipped=%d malformed=%d\n", stats.Read, stats.Emitted, stats.Skipped, stats.Malformed)
	return nil
}

func runReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "normalized JSONL input path, or - for stdin")
	output := fs.String("output", "-", "replay summary JSON output path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	summary, err := replay.AnalyzeFiles(*input, *output, replay.Options{})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "replay: read=%d accepted=%d duplicate=%d skipped=%d malformed=%d ips=%d\n",
		summary.Stats.Read,
		summary.Stats.Accepted,
		summary.Stats.Duplicate,
		summary.Stats.Skipped,
		summary.Stats.Malformed,
		len(summary.Windows),
	)
	return nil
}

func runEvidence(args []string) error {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "normalized JSONL input path, or - for stdin")
	output := fs.String("output", "-", "evidence JSON output path, or - for stdout")
	window := fs.Duration("window", 10*time.Minute, "evidence window, for example 10m or 1h")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	result, err := evidence.AnalyzeFiles(*input, *output, evidence.Options{Window: *window})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "evidence: read=%d accepted=%d duplicate=%d skipped=%d malformed=%d evidence=%d\n",
		result.Stats.Read,
		result.Stats.Accepted,
		result.Stats.Duplicate,
		result.Stats.Skipped,
		result.Stats.Malformed,
		len(result.Evidence),
	)
	return nil
}

func runRisk(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing risk command")
	}
	switch args[0] {
	case "inspect":
		return runRiskInspect(args[1:])
	case "batch":
		return runRiskBatch(args[1:])
	case "list":
		return runRiskList(args[1:])
	default:
		return fmt.Errorf("unknown risk command: %s", args[0])
	}
}

func runRiskInspect(args []string) error {
	fs := flag.NewFlagSet("risk inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "evidence JSON input path, or - for stdin")
	ip := fs.String("ip", "", "IP address to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *ip == "" {
		return fmt.Errorf("--ip is required")
	}

	snapshot, err := risk.InspectFile(*input, risk.InspectOptions{IP: *ip})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "risk inspect: ip=%s score=%d level=%s evidence=%d\n", snapshot.IP, snapshot.Score, snapshot.Level, len(snapshot.EvidenceIDs))
	return writeJSON(os.Stdout, snapshot)
}

func runRiskBatch(args []string) error {
	fs := flag.NewFlagSet("risk batch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "evidence JSON input path, or - for stdin")
	output := fs.String("output", "", "risk snapshots JSON output path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	result, err := risk.BatchFile(*input, *output)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "risk batch: snapshots=%d\n", len(result.Snapshots))
	return nil
}

func runRiskList(args []string) error {
	fs := flag.NewFlagSet("risk list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "risk snapshots JSON input path, or - for stdin")
	output := fs.String("output", "-", "risk list JSON output path, or - for stdout")
	minLevel := fs.String("min-level", "suspicious", "minimum risk level: normal, suspicious, high, confirmed")
	limit := fs.Int("limit", 50, "maximum snapshots to output; 0 means unlimited")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	result, err := risk.ListFile(*input, *output, risk.ListOptions{MinLevel: *minLevel, Limit: *limit})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "risk list: min_level=%s snapshots=%d\n", result.MinLevel, len(result.Snapshots))
	return nil
}

func runShadow(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing shadow command")
	}
	switch args[0] {
	case "run":
		return runShadowRun(args[1:])
	default:
		return fmt.Errorf("unknown shadow command: %s", args[0])
	}
}

func runShadowRun(args []string) error {
	fs := flag.NewFlagSet("shadow run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	eve := fs.String("eve", "/var/log/suricata/eve.json", "Suricata EVE JSONL path")
	zeekDHCP := fs.String("zeek-dhcp", "", "optional Zeek dhcp.log path to append as device events")
	zeekSoftware := fs.String("zeek-software", "", "optional Zeek software.log path to append as device events")
	state := fs.String("state", "data/shadow/state.json", "shadow offset state path")
	outDir := fs.String("out-dir", "data/shadow", "shadow output directory")
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	window := fs.Duration("window", 10*time.Minute, "evidence window, for example 10m or 1h")
	minLevel := fs.String("min-level", "suspicious", "risk list minimum level")
	limit := fs.Int("limit", 50, "risk list maximum snapshots")
	retention := fs.Duration("retention", 7*24*time.Hour, "run directory retention, for example 168h")
	storageMode := fs.String("storage-mode", "file", "storage mode: file, db, or dual")
	postgresDSN := fs.String("postgres-dsn", "", "PostgreSQL DSN for production evidence/risk/audit storage")
	clickHouseDSN := fs.String("clickhouse-dsn", "", "ClickHouse HTTP URL for production event/diagnostic storage")
	if err := fs.Parse(args); err != nil {
		return err
	}

	summary, err := shadow.Run(shadow.Options{
		EVEPath:          *eve,
		ZeekDHCPPath:     *zeekDHCP,
		ZeekSoftwarePath: *zeekSoftware,
		StatePath:        *state,
		OutDir:           *outDir,
		SensorID:         *sensorID,
		Window:           *window,
		ListMinLevel:     *minLevel,
		ListLimit:        *limit,
		Retention:        *retention,
		StorageMode:      *storageMode,
		PostgresDSN:      *postgresDSN,
		ClickHouseDSN:    *clickHouseDSN,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "shadow run: normalized=%d evidence=%d risks=%d list=%d run_dir=%s\n",
		summary.Normalized.Emitted,
		summary.EvidenceCount,
		summary.RiskCount,
		summary.RiskListCount,
		summary.RunDir,
	)
	return writeJSON(os.Stdout, summary)
}

func runControlPlane(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing control-plane command")
	}
	switch args[0] {
	case "serve":
		return runControlPlaneServe(args[1:])
	default:
		return fmt.Errorf("unknown control-plane command: %s", args[0])
	}
}

func runValidate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing validate command")
	}
	switch args[0] {
	case "known-devices":
		return runValidateKnownDevices(args[1:])
	default:
		return fmt.Errorf("unknown validate command: %s", args[0])
	}
}

func runEvaluate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing evaluate command")
	}
	switch args[0] {
	case "shadow":
		return runEvaluateShadow(args[1:])
	default:
		return fmt.Errorf("unknown evaluate command: %s", args[0])
	}
}

func runEvaluateShadow(args []string) error {
	fs := flag.NewFlagSet("evaluate shadow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	shadowDir := fs.String("shadow-dir", "data/shadow", "shadow run and label directory")
	fromRaw := fs.String("from", "", "optional RFC3339 or YYYY-MM-DD window start")
	toRaw := fs.String("to", "", "optional RFC3339 or YYYY-MM-DD window end")
	requiredDays := fs.Int("required-days", 7, "minimum continuous run and reviewed days")
	samplesPerDay := fs.Int("samples-per-level", 10, "daily exported samples per risk level")
	exportDir := fs.String("daily-export-dir", "", "optional directory for stratified daily review samples")
	postgresDSN := fs.String("postgres-dsn", "", "optional PostgreSQL DSN for labels written by DB/dual control planes")
	output := fs.String("output", "-", "evaluation report JSON path, or - for stdout")
	strict := fs.Bool("strict", false, "return an error unless the shadow evaluation is ready")
	if err := fs.Parse(args); err != nil {
		return err
	}
	from, err := parseEvaluationTime(*fromRaw, false)
	if err != nil {
		return fmt.Errorf("parse --from: %w", err)
	}
	to, err := parseEvaluationTime(*toRaw, true)
	if err != nil {
		return fmt.Errorf("parse --to: %w", err)
	}
	report, err := evaluation.EvaluateShadow(evaluation.ShadowOptions{
		ShadowDir: *shadowDir, From: from, To: to, RequiredDays: *requiredDays,
		SamplesPerDay: *samplesPerDay, ExportDir: *exportDir, PostgresDSN: *postgresDSN,
	})
	if err != nil {
		return err
	}
	out, closeOutput, err := openOutput(*output)
	if err != nil {
		return err
	}
	defer closeOutput()
	if err := writeJSON(out, report); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "evaluate shadow: ready=%t runs=%d days=%d continuous=%d reviewed_days=%d snapshots=%d reviewed=%d blockers=%d\n",
		report.Ready, report.RunCount, report.ObservedDays, report.LongestContinuousDays, report.DaysWithReviews,
		report.RiskSnapshotCount, report.ReviewedSnapshotCount, len(report.Blockers))
	if *strict && !report.Ready {
		return fmt.Errorf("shadow evaluation is not ready: %s", strings.Join(report.Blockers, "; "))
	}
	return nil
}

func parseEvaluationTime(raw string, endOfDay bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed, nil
	}
	parsed, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD")
	}
	if endOfDay {
		return parsed.Add(24*time.Hour - time.Nanosecond), nil
	}
	return parsed, nil
}

func runValidateKnownDevices(args []string) error {
	fs := flag.NewFlagSet("validate known-devices", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "known devices CSV path, or - for stdin")
	events := fs.String("events", "", "optional normalized identity JSONL path to compare against")
	output := fs.String("output", "-", "validation report JSON path, or - for stdout")
	strict := fs.Bool("strict", false, "require 30-50 sample acceptance coverage and a passing identity comparison")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	in, closeInput, err := openInput(*input)
	if err != nil {
		return err
	}
	defer closeInput()
	out, closeOutput, err := openOutput(*output)
	if err != nil {
		return err
	}
	defer closeOutput()

	var report validation.KnownDeviceValidationReport
	if *events != "" {
		normalizedEvents, err := readNormalizedEventsFile(*events)
		if err != nil {
			return err
		}
		report, err = validation.AnalyzeKnownDeviceCSVWithIdentityState(in, store.BuildIdentityState(normalizedEvents))
		if err != nil {
			return err
		}
	} else {
		report, err = validation.AnalyzeKnownDeviceCSV(in)
		if err != nil {
			return err
		}
	}
	if err := writeJSON(out, report); err != nil {
		return err
	}
	comparisonFailed := 0
	if report.Comparison != nil {
		comparisonFailed = report.Comparison.Failed
	}
	fmt.Fprintf(os.Stderr, "validate known-devices: valid=%t samples=%d errors=%d warnings=%d comparison_failed=%d\n",
		report.Valid,
		report.Coverage.Total,
		len(report.Errors),
		len(report.Warnings),
		comparisonFailed,
	)
	if !report.Valid {
		return fmt.Errorf("known devices validation failed with %d structural error(s), %d comparison failure(s)", len(report.Errors), comparisonFailed)
	}
	if *strict && !report.AcceptanceReady {
		return fmt.Errorf("known devices acceptance is not ready: warnings=%d comparison_present=%t", len(report.Warnings), report.Comparison != nil)
	}
	return nil
}

func readNormalizedEventsFile(path string) ([]normalized.Event, error) {
	input, closeInput, err := openInput(path)
	if err != nil {
		return nil, err
	}
	defer closeInput()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	events := []normalized.Event{}
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var event normalized.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, fmt.Errorf("decode normalized events line %d: %w", line, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read normalized events: %w", err)
	}
	return events, nil
}

func runControlPlaneServe(args []string) error {
	fs := flag.NewFlagSet("control-plane serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", ":8080", "HTTP listen address")
	shadowDir := fs.String("shadow-dir", "/opt/proxy-sentinel/data/shadow", "shadow output directory")
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	frontendDir := fs.String("frontend-dir", "", "optional frontend dist directory to serve")
	readOnly := fs.Bool("read-only", true, "disable mutating review and reload endpoints")
	storageMode := fs.String("storage-mode", "file", "storage mode: file, db, or dual")
	postgresDSN := fs.String("postgres-dsn", "", "PostgreSQL DSN for production business storage")
	clickHouseDSN := fs.String("clickhouse-dsn", "", "ClickHouse HTTP URL for production event and diagnostic storage")
	eventRetention := fs.Duration("event-retention", 7*24*time.Hour, "normalized event retention target, documented for DB deployments")
	diagnosticRetention := fs.Duration("diagnostic-retention", 30*24*time.Hour, "diagnostic retention target, documented for DB deployments")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "control-plane: addr=%s shadow_dir=%s sensor_id=%s storage_mode=%s read_only=%t event_retention=%s diagnostic_retention=%s\n", *addr, *shadowDir, *sensorID, *storageMode, *readOnly, eventRetention.String(), diagnosticRetention.String())
	return controlplane.Serve(controlplane.Options{
		Addr:          *addr,
		ShadowDir:     *shadowDir,
		SensorID:      *sensorID,
		FrontendDir:   *frontendDir,
		ReadOnly:      *readOnly,
		StorageMode:   *storageMode,
		PostgresDSN:   *postgresDSN,
		ClickHouseDSN: *clickHouseDSN,
		CollectorKind: "suricata",
		InterfaceName: "ens1f1",
	})
}

func usageError() error {
	return fmt.Errorf("usage: proxy-sentinel adapter suricata --input eve.json --output events.jsonl\n       proxy-sentinel adapter zeek --input dhcp.log --output events.jsonl\n       proxy-sentinel adapter zeek --input software.log --output events.jsonl\n       proxy-sentinel adapter identity --source radius --input radius.jsonl --output events.jsonl\n       proxy-sentinel replay --input events.jsonl [--output summary.json]\n       proxy-sentinel evidence --input events.jsonl [--output evidence.json]\n       proxy-sentinel risk batch --input evidence.json --output risk-snapshots.json\n       proxy-sentinel risk list --input risk-snapshots.json [--min-level suspicious]\n       proxy-sentinel risk inspect --input evidence.json --ip 10.1.2.3\n       proxy-sentinel shadow run --eve /var/log/suricata/eve.json [--zeek-dhcp /opt/proxy-sentinel/data/zeek/logs/current/dhcp.log] [--zeek-software /opt/proxy-sentinel/data/zeek/logs/current/software.log] --state data/shadow/state.json --out-dir data/shadow\n       proxy-sentinel evaluate shadow --shadow-dir data/shadow [--daily-export-dir data/shadow/review-exports] --output report.json\n       proxy-sentinel control-plane serve --addr :8080 --shadow-dir data/shadow --frontend-dir frontend/dist --read-only\n       proxy-sentinel validate known-devices --input examples/known-devices-template.csv [--events normalized-identity.jsonl] [--strict] --output -")
}

func openInput(path string) (*os.File, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	return file, file.Close, nil
}

func openOutput(path string) (*os.File, func() error, error) {
	if path == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output: %w", err)
	}
	return file, file.Close, nil
}

func writeJSON(output *os.File, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
