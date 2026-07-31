package suricata

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConvertFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "suricata", "eve-mirror-20260724-131645-redacted.jsonl")
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{SensorID: "lab-30"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 1000 || stats.Emitted != 1000 || stats.Malformed != 0 || stats.Skipped != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	for _, eventType := range []string{"flow", "dns", "tls", "http"} {
		if stats.ByType[eventType] != 250 {
			t.Fatalf("expected 250 %s events, got %d", eventType, stats.ByType[eventType])
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	line := 0
	for scanner.Scan() {
		line++
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("line %d is not json: %v", line, err)
		}
		requireString(t, event, "schema_version", "v1")
		requireString(t, event, "source", "suricata")
		requireNonEmptyString(t, event, "event_id")
		requireNonEmptyString(t, event, "timestamp")
		if _, err := time.Parse(time.RFC3339Nano, event["timestamp"].(string)); err != nil {
			t.Fatalf("line %d timestamp is not RFC3339Nano: %v", line, err)
		}
		requireNestedString(t, event, "subject", "ip")
		requireNestedString(t, event, "flow", "src_ip")
		requireNestedString(t, event, "flow", "dst_ip")
		requireNestedString(t, event, "flow", "proto")
		requireNestedString(t, event, "flow", "direction")
		requireNestedString(t, event, "raw_ref", "backend")
		if _, ok := event["raw_ref"].(map[string]any)["line_offset"]; !ok {
			t.Fatalf("line %d missing raw_ref.line_offset", line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if line != 1000 {
		t.Fatalf("expected 1000 normalized lines, got %d", line)
	}
}

func TestConvertSkipsMalformedAndUnsupportedLines(t *testing.T) {
	input := bytes.NewBufferString("{bad json\n" +
		"{\"timestamp\":\"2026-07-24T13:16:46.672238+0800\",\"event_type\":\"stats\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"10.0.0.2\",\"proto\":\"TCP\"}\n" +
		"{\"timestamp\":\"2026-07-24T13:16:46.672238+0800\",\"event_type\":\"tls\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"198.51.100.2\",\"src_port\":12345,\"dest_port\":443,\"proto\":\"TCP\",\"tls\":{\"sni\":\"example.test\"}}\n")

	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 3 || stats.Emitted != 1 || stats.Malformed != 1 || stats.Skipped != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestConvertAlertAndQUICEvents(t *testing.T) {
	input := bytes.NewBufferString(
		"{\"timestamp\":\"2026-07-24T13:16:46.672238+0800\",\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"198.51.100.2\",\"src_port\":12345,\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"signature_id\":1001,\"signature\":\"Known proxy tunnel\",\"category\":\"Policy\",\"severity\":2,\"action\":\"allowed\"}}\n" +
			"{\"timestamp\":\"2026-07-24T13:16:47.672238+0800\",\"event_type\":\"quic\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"198.51.100.3\",\"src_port\":12346,\"dest_port\":443,\"proto\":\"UDP\",\"quic\":{\"sni\":\"vpn.example.test\",\"version\":\"1\",\"ja4\":\"q_ja4\",\"alpn\":\"h3\"}}\n")
	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{SensorID: "lab-30"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 2 || stats.Emitted != 2 || stats.ByType["alert"] != 1 || stats.ByType["quic"] != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	events := []map[string]any{}
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 2 {
		t.Fatalf("expected two events, got %+v", events)
	}
	requireString(t, events[0], "type", "alert")
	requireNestedString(t, events[0], "payload", "signature")
	requireString(t, events[1], "type", "quic")
	requireNestedString(t, events[1], "payload", "sni")
	requireNestedString(t, events[1], "payload", "ja4")
}

func requireString(t *testing.T, event map[string]any, key string, expected string) {
	t.Helper()
	value, ok := event[key].(string)
	if !ok || value != expected {
		t.Fatalf("expected %s=%q, got %#v", key, expected, event[key])
	}
}

func requireNonEmptyString(t *testing.T, event map[string]any, key string) {
	t.Helper()
	value, ok := event[key].(string)
	if !ok || value == "" {
		t.Fatalf("expected non-empty string %s, got %#v", key, event[key])
	}
}

func requireNestedString(t *testing.T, event map[string]any, objectKey, fieldKey string) {
	t.Helper()
	object, ok := event[objectKey].(map[string]any)
	if !ok {
		t.Fatalf("expected object %s, got %#v", objectKey, event[objectKey])
	}
	value, ok := object[fieldKey].(string)
	if !ok || value == "" {
		t.Fatalf("expected non-empty string %s.%s, got %#v", objectKey, fieldKey, object[fieldKey])
	}
}
