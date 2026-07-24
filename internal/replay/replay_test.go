package replay

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/adapter/suricata"
)

func TestAnalyzeConvertedFixture(t *testing.T) {
	inputPath := filepath.Join("..", "..", "examples", "suricata", "eve-mirror-20260724-131645-redacted.jsonl")
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	var normalized bytes.Buffer
	adapterStats, err := suricata.Convert(input, &normalized, suricata.Options{SensorID: "lab-30"})
	if err != nil {
		t.Fatal(err)
	}
	if adapterStats.Emitted != 1000 {
		t.Fatalf("expected 1000 normalized events, got %d", adapterStats.Emitted)
	}

	first, err := Analyze(bytes.NewReader(normalized.Bytes()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyze(bytes.NewReader(normalized.Bytes()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Stats.Accepted != 1000 || first.Stats.Duplicate != 0 || first.Stats.Malformed != 0 || first.Stats.Skipped != 0 {
		t.Fatalf("unexpected replay stats: %+v", first.Stats)
	}
	if len(first.Windows) == 0 {
		t.Fatal("expected per-ip windows")
	}

	firstJSON := mustJSON(t, first)
	secondJSON := mustJSON(t, second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("expected deterministic replay summary")
	}

	foundNonEmptyWindow := false
	for _, ip := range first.Windows {
		if len(ip.Windows) != 4 {
			t.Fatalf("expected 4 windows for %s, got %d", ip.IP, len(ip.Windows))
		}
		for _, window := range ip.Windows {
			if window.EventCount > 0 {
				foundNonEmptyWindow = true
			}
		}
	}
	if !foundNonEmptyWindow {
		t.Fatal("expected at least one non-empty window")
	}
}

func TestAnalyzeDeduplicatesAndSkipsBadEvents(t *testing.T) {
	input := bytes.NewBufferString(`{"schema_version":"v1","event_id":"same","source":"suricata","type":"dns","timestamp":"2026-07-24T13:16:47.547787+08:00","subject":{"ip":"10.0.0.1"},"flow":{"src_ip":"10.0.0.1","dst_ip":"198.51.100.1","proto":"udp","direction":"outbound"},"payload":{"query":"example.test"},"confidence":1}` + "\n" +
		`{"schema_version":"v1","event_id":"same","source":"suricata","type":"dns","timestamp":"2026-07-24T13:16:47.547787+08:00","subject":{"ip":"10.0.0.1"},"flow":{"src_ip":"10.0.0.1","dst_ip":"198.51.100.1","proto":"udp","direction":"outbound"},"payload":{"query":"example.test"},"confidence":1}` + "\n" +
		`{"schema_version":"v1","event_id":"bad-time","source":"suricata","type":"dns","timestamp":"not-time","subject":{"ip":"10.0.0.1"},"flow":{"src_ip":"10.0.0.1","dst_ip":"198.51.100.1","proto":"udp","direction":"outbound"},"confidence":1}` + "\n" +
		`{bad json` + "\n")

	summary, err := Analyze(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Stats.Read != 4 || summary.Stats.Accepted != 1 || summary.Stats.Duplicate != 1 || summary.Stats.Skipped != 1 || summary.Stats.Malformed != 1 {
		t.Fatalf("unexpected stats: %+v", summary.Stats)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
