package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/adapter/suricata"
)

func TestAnalyzeEmitsExplainableEvidence(t *testing.T) {
	input := bytes.NewBufferString(
		normalizedLine("ua-1", "http", map[string]any{"user_agent": "UA-A", "host": "a.example.test"}, map[string]any{"dst_port": 80}) + "\n" +
			normalizedLine("ua-2", "http", map[string]any{"user_agent": "UA-B", "host": "b.example.test"}, map[string]any{"dst_port": 443}) + "\n" +
			normalizedLine("tls-1", "tls", map[string]any{"ja3": "ja3-a", "sni": "c.example.test"}, map[string]any{"dst_port": 8443}) + "\n" +
			normalizedLine("tls-2", "tls", map[string]any{"ja4": "ja4-a", "sni": "d.example.test"}, map[string]any{"dst_port": 8080}) + "\n" +
			normalizedLine("flow-1", "flow", map[string]any{}, map[string]any{"dst_port": 22}) + "\n")

	result, err := Analyze(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.Accepted != 5 {
		t.Fatalf("unexpected stats: %+v", result.Stats)
	}

	byType := map[string]Evidence{}
	for _, ev := range result.Evidence {
		byType[ev.Type] = ev
		if ev.EvidenceID == "" || ev.IP == "" || ev.Window == "" || ev.Score == 0 || ev.Confidence == 0 || ev.Severity == "" || ev.Reason == "" || ev.CreatedAt == "" {
			t.Fatalf("evidence is missing required fields: %+v", ev)
		}
		if len(ev.Samples) == 0 {
			t.Fatalf("evidence missing samples: %+v", ev)
		}
	}

	for _, expected := range []string{"multi_user_agent", "multi_ja3_ja4", "port_distribution"} {
		if _, ok := byType[expected]; !ok {
			t.Fatalf("missing evidence type %s in %+v", expected, byType)
		}
	}
}

func TestAnalyzeConvertedFixtureIsDeterministic(t *testing.T) {
	inputPath := filepath.Join("..", "..", "examples", "suricata", "eve-mirror-20260724-131645-redacted.jsonl")
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	var normalized bytes.Buffer
	_, err = suricata.Convert(input, &normalized, suricata.Options{SensorID: "lab-30"})
	if err != nil {
		t.Fatal(err)
	}

	first, err := Analyze(bytes.NewReader(normalized.Bytes()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyze(bytes.NewReader(normalized.Bytes()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Stats.Accepted != 1000 {
		t.Fatalf("expected 1000 accepted events, got %+v", first.Stats)
	}
	if len(first.Evidence) == 0 {
		t.Fatal("expected fixture to produce evidence")
	}
	if !bytes.Equal(mustJSON(t, first), mustJSON(t, second)) {
		t.Fatal("expected deterministic evidence output")
	}
}

func normalizedLine(id string, eventType string, payload map[string]any, flow map[string]any) string {
	event := map[string]any{
		"schema_version": "v1",
		"event_id":       id,
		"source":         "suricata",
		"type":           eventType,
		"timestamp":      "2026-07-24T13:20:00Z",
		"subject":        map[string]any{"ip": "10.0.0.1"},
		"flow": map[string]any{
			"src_ip":    "10.0.0.1",
			"dst_ip":    "198.51.100.1",
			"proto":     "tcp",
			"direction": "outbound",
		},
		"payload":    payload,
		"confidence": 1,
	}
	for key, value := range flow {
		event["flow"].(map[string]any)[key] = value
	}
	data, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
