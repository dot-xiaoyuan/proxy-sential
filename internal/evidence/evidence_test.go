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

func TestAnalyzeEmitsDHCPDeviceFingerprintEvidence(t *testing.T) {
	input := bytes.NewBufferString(
		normalizedLine("device-apple", "device", map[string]any{
			"origin":            "dhcp",
			"hostname":          "Yuan-iPhone",
			"vendor_class":      "Apple iOS DHCP",
			"requested_options": "1,3,6,15,119,252",
			"client_mac":        "aa:bb:cc:dd:ee:01",
			"device_hint":       "apple",
		}, map[string]any{"dst_port": 67}) + "\n" +
			normalizedLine("device-windows", "device", map[string]any{
				"origin":            "dhcp",
				"hostname":          "DESKTOP-9NQ1",
				"vendor_class":      "MSFT 5.0",
				"requested_options": "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
				"client_mac":        "aa:bb:cc:dd:ee:02",
				"device_hint":       "windows",
			}, map[string]any{"dst_port": 67}) + "\n")

	result, err := Analyze(input, Options{})
	if err != nil {
		t.Fatal(err)
	}

	byType := map[string]Evidence{}
	for _, ev := range result.Evidence {
		byType[ev.Type] = ev
	}
	for _, expected := range []string{"dhcp_device_fingerprint", "device_fingerprint_conflict"} {
		ev, ok := byType[expected]
		if !ok {
			t.Fatalf("missing evidence type %s in %+v", expected, byType)
		}
		if ev.Score == 0 || ev.Confidence < 0.8 || len(ev.Samples) == 0 || ev.Reason == "" {
			t.Fatalf("unexpected device evidence: %+v", ev)
		}
	}
}

func TestAnalyzeEmitsAccountSharingEvidence(t *testing.T) {
	input := bytes.NewBufferString(
		identityLine("id-1", "2026000123", "10.0.0.8", "aa:bb:cc:dd:ee:01", "Dorm-A-AP01", "endpoint", map[string]any{}) + "\n" +
			identityLine("id-2", "2026000123", "10.0.0.9", "aa:bb:cc:dd:ee:02", "Dorm-B-AP09", "endpoint", map[string]any{}) + "\n")

	result, err := Analyze(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]Evidence{}
	for _, ev := range result.Evidence {
		byType[ev.Type] = ev
	}
	ev, ok := byType["account_concurrent_macs"]
	if !ok {
		t.Fatalf("missing account_concurrent_macs in %+v", byType)
	}
	if ev.SubjectType != "account" || ev.SubjectID != "2026000123" || ev.AccountID != "2026000123" || ev.Score < 60 {
		t.Fatalf("unexpected account evidence: %+v", ev)
	}
	if _, ok := byType["account_concurrent_access"]; !ok {
		t.Fatalf("missing account_concurrent_access in %+v", byType)
	}
}

func TestAnalyzeDoesNotCountInfrastructureAsAccountEndpoint(t *testing.T) {
	input := bytes.NewBufferString(
		identityLine("infra-1", "2026000123", "10.0.0.1", "aa:bb:cc:dd:ee:01", "gw", "gateway", map[string]any{}) + "\n" +
			identityLine("infra-2", "2026000123", "10.0.0.2", "aa:bb:cc:dd:ee:02", "dns", "server", map[string]any{}) + "\n")
	result, err := Analyze(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range result.Evidence {
		if ev.SubjectType == "account" {
			t.Fatalf("infrastructure events should not produce account endpoint evidence: %+v", ev)
		}
	}
}

func TestAnalyzeEmitsAuthObservedMACMismatchEvidence(t *testing.T) {
	input := bytes.NewBufferString(
		identityLine("id-mismatch", "2026000123", "10.0.0.8", "aa:bb:cc:dd:ee:01", "Dorm-A-AP01", "endpoint", map[string]any{
			"auth_mac":     "aa:bb:cc:dd:ee:01",
			"observed_mac": "aa:bb:cc:dd:ee:02",
		}) + "\n")
	result, err := Analyze(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range result.Evidence {
		if ev.Type == "auth_observed_mac_mismatch" {
			if ev.SubjectType != "account" || ev.SubjectID != "2026000123" || ev.Score < 60 {
				t.Fatalf("unexpected mismatch evidence: %+v", ev)
			}
			return
		}
	}
	t.Fatalf("missing auth_observed_mac_mismatch evidence: %+v", result.Evidence)
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

func identityLine(id, accountID, ip, mac, accessID, entityRole string, payload map[string]any) string {
	event := map[string]any{
		"schema_version": "v1",
		"event_id":       id,
		"source":         "radius",
		"type":           "identity",
		"timestamp":      "2026-07-24T13:20:00Z",
		"subject": map[string]any{
			"ip":                  ip,
			"account_id":          accountID,
			"endpoint_id":         "mac:" + mac,
			"mac":                 mac,
			"access_id":           accessID,
			"entity_role":         entityRole,
			"identity_confidence": 0.92,
		},
		"flow": map[string]any{
			"src_ip":    ip,
			"dst_ip":    "0.0.0.0",
			"proto":     "other",
			"direction": "unknown",
		},
		"payload":    payload,
		"confidence": 0.92,
	}
	data, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	return string(data)
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
