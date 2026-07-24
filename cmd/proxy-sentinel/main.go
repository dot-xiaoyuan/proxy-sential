package main

import (
	"flag"
	"fmt"
	"os"

	"proxy-sentinel/internal/adapter/suricata"
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

func usageError() error {
	return fmt.Errorf("usage: proxy-sentinel adapter suricata --input eve.json --output events.jsonl")
}
