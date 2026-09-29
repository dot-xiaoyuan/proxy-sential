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

func TestConvertRouterIdentityFields(t *testing.T) {
	input := bytes.NewBufferString(
		`{"timestamp":"2026-09-24T09:30:00.000000+0800","event_type":"http","src_ip":"10.0.0.2","dest_ip":"10.0.0.1","src_port":50000,"dest_port":80,"proto":"TCP","ether":{"src_mac":"00-46-4B-12-34-56","dest_mac":"00:00:5e:00:53:01"},"vlan":[120],"http":{"hostname":"ar6140.local","http_server":"Huawei AR Web","http_title":"AR6140 Management"}}` + "\n" +
			`{"timestamp":"2026-09-24T09:30:01.000000+0800","event_type":"tls","src_ip":"10.0.0.2","dest_ip":"10.0.0.1","src_port":50001,"dest_port":443,"proto":"TCP","ether":{"src_mac":"00:46:4b:12:34:56"},"vlan":120,"tls":{"sni":"ar6140.local","subject":"CN=Huawei AR6140","issuerdn":"CN=Huawei","serial":"01AB","fingerprint":"AA:BB","san":["ar6140.local"]}}` + "\n" +
			`{"timestamp":"2026-09-24T09:30:02.000000+0800","event_type":"alert","src_ip":"10.0.0.2","dest_ip":"10.0.0.1","proto":"TCP","alert":{"signature_id":900001,"signature":"Router management login","category":"Device management","metadata":{"device":["router"]}}}` + "\n")
	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{})
	if err != nil || stats.Emitted != 3 {
		t.Fatalf("unexpected conversion stats=%+v err=%v", stats, err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	var events []map[string]any
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if events[0]["subject"].(map[string]any)["mac"] != "00:46:4b:12:34:56" || events[0]["payload"].(map[string]any)["vlan"] != "120" || events[0]["payload"].(map[string]any)["server"] != "Huawei AR Web" || events[0]["payload"].(map[string]any)["title"] != "AR6140 Management" {
		t.Fatalf("unexpected HTTP identity fields: %+v", events[0])
	}
	tls := events[1]["payload"].(map[string]any)
	for _, key := range []string{"certificate_subject", "certificate_issuer", "certificate_serial", "certificate_fingerprint", "certificate_san"} {
		if tls[key] == nil {
			t.Fatalf("missing TLS %s: %+v", key, tls)
		}
	}
	alert := events[2]["payload"].(map[string]any)
	if alert["signature"] != "Router management login" || alert["category"] != "Device management" || alert["metadata"] == nil {
		t.Fatalf("missing alert management clues: %+v", alert)
	}
}

func TestConvertPreservesObservedApplicationProtocol(t *testing.T) {
	input := bytes.NewBufferString("{\"timestamp\":\"2026-07-24T13:16:46.672238+0800\",\"event_type\":\"flow\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"198.51.100.2\",\"proto\":\"TCP\",\"app_proto\":\"http2\",\"flow\":{}}\n")
	var output bytes.Buffer
	if _, err := Convert(input, &output, Options{}); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	requireNestedString(t, event, "flow", "app_protocol")
	if event["flow"].(map[string]any)["app_protocol"] != "http2" {
		t.Fatalf("unexpected app protocol: %#v", event)
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

func TestEventIDIsStableAcrossReplayOffsets(t *testing.T) {
	raw := []byte(`{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}`)
	first, err := convertLine(raw, 1, Options{SensorID: "sensor-a"})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := convertLine(raw, 9001, Options{SensorID: "sensor-a"})
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID != replayed.EventID {
		t.Fatalf("event id changed across replay: %s != %s", first.EventID, replayed.EventID)
	}
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
