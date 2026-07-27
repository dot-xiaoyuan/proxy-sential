package shadow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunReadsIncrementally(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	first := eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")
	second := eveLine("2", "10.0.0.1", "198.51.100.2", "b.example.test")
	if err := os.WriteFile(evePath, []byte(first), 0644); err != nil {
		t.Fatal(err)
	}

	firstSummary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if firstSummary.PreviousOffset != 0 || firstSummary.NewOffset <= 0 || firstSummary.Normalized.Emitted != 1 {
		t.Fatalf("unexpected first summary: %+v", firstSummary)
	}

	file, err := os.OpenFile(evePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(second); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	secondSummary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if secondSummary.PreviousOffset != firstSummary.NewOffset || secondSummary.Normalized.Emitted != 1 {
		t.Fatalf("unexpected second summary: %+v", secondSummary)
	}

	emptySummary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if emptySummary.PreviousOffset != secondSummary.NewOffset || emptySummary.Normalized.Emitted != 0 || emptySummary.EvidenceCount != 0 || emptySummary.RiskCount != 0 {
		t.Fatalf("unexpected empty summary: %+v", emptySummary)
	}
}

func TestRunRestartsWhenEVEIsTruncated(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")+eveLine("2", "10.0.0.2", "198.51.100.2", "b.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evePath, []byte(eveLine("3", "10.0.0.3", "198.51.100.3", "c.example.test")), 0644); err != nil {
		t.Fatal(err)
	}

	summary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Truncated || summary.PreviousOffset != 0 || summary.Normalized.Emitted != 1 {
		t.Fatalf("unexpected truncated summary: %+v", summary)
	}
}

func TestRunWritesExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	summary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"normalized", "evidence", "risk_snapshots", "risk_list_suspicious", "run_summary"} {
		path, ok := summary.Files[name].(string)
		if !ok || path == "" {
			t.Fatalf("missing file %s in %+v", name, summary.Files)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	var state State
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.Offset != summary.NewOffset || state.EVEPath != evePath {
		t.Fatalf("unexpected state: %+v summary=%+v", state, summary)
	}
}

func eveLine(id string, srcIP string, dstIP string, host string) string {
	return `{"timestamp":"2026-07-24T13:16:47.547787+0800","flow_id":` + id + `,"in_iface":"ens1f1","event_type":"http","src_ip":"` + srcIP + `","src_port":50000,"dest_ip":"` + dstIP + `","dest_port":80,"proto":"TCP","http":{"hostname":"` + host + `","url":"/","http_user_agent":"UA","http_method":"GET"}}` + "\n"
}
