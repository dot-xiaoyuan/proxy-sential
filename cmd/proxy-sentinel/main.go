package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/controlplane"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/replay"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/shadow"
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
		EVEPath:       *eve,
		StatePath:     *state,
		OutDir:        *outDir,
		SensorID:      *sensorID,
		Window:        *window,
		ListMinLevel:  *minLevel,
		ListLimit:     *limit,
		Retention:     *retention,
		StorageMode:   *storageMode,
		PostgresDSN:   *postgresDSN,
		ClickHouseDSN: *clickHouseDSN,
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
	return fmt.Errorf("usage: proxy-sentinel adapter suricata --input eve.json --output events.jsonl\n       proxy-sentinel replay --input events.jsonl [--output summary.json]\n       proxy-sentinel evidence --input events.jsonl [--output evidence.json]\n       proxy-sentinel risk batch --input evidence.json --output risk-snapshots.json\n       proxy-sentinel risk list --input risk-snapshots.json [--min-level suspicious]\n       proxy-sentinel risk inspect --input evidence.json --ip 10.1.2.3\n       proxy-sentinel shadow run --eve /var/log/suricata/eve.json --state data/shadow/state.json --out-dir data/shadow\n       proxy-sentinel control-plane serve --addr :8080 --shadow-dir data/shadow --frontend-dir frontend/dist --read-only")
}

func writeJSON(output *os.File, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
