package evidence

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestFeatureEventPreservesEvidenceButDropsUnneededBody(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	events := []normalized.Event{
		{EventID: "a", Timestamp: now.Format(time.RFC3339Nano), Type: "device", Source: "zeek", SourceEventType: "dhcp",
			Subject: map[string]any{"ip": "192.0.2.8", "account_id": "account-a", "mac": "02:00:00:00:00:08", "endpoint_id": "endpoint-a", "access_id": "access-a", "entity_role": "endpoint", "unrelated_subject": "discard"},
			Payload: map[string]any{"origin": "dhcp", "ttl": 62, "hostname": "ipad-8", "vendor_class": "Apple", "client_mac": "02:00:00:00:00:08", "query": "vpn.example.test", "user_agent": "iPhone", "software_name": "software", "unrelated_payload": "discard"},
			Flow:    map[string]any{"proto": "udp", "dst_port": 443, "dst_ip": "198.51.100.1", "direction": "egress", "unrelated_flow": "discard"}, RawRef: map[string]any{"private": "discard"}},
		{EventID: "b", Timestamp: now.Add(-time.Second).Format(time.RFC3339Nano), Type: "alert", Source: "suricata",
			Subject: map[string]any{"ip": "192.0.2.8", "account_id": "account-a", "entity_role": "endpoint"},
			Payload: map[string]any{"signature": "VPN tunnel", "signature_id": 123, "category": "proxy", "severity": 2, "metadata": map[string]any{"proxy_sentinel_confidence": []any{"high"}, "other": "discard"}},
			Flow:    map[string]any{"dst_port": 443}},
	}
	projected := make([]normalized.Event, len(events))
	for index, event := range events {
		projected[index] = FeatureEvent(event)
	}
	if projected[0].Payload["unrelated_payload"] != nil || projected[0].Subject["unrelated_subject"] != nil || projected[0].Flow["unrelated_flow"] != nil || projected[0].RawRef != nil || projected[1].Payload["metadata"].(map[string]any)["other"] != nil {
		t.Fatalf("feature projection retained unrelated full-body fields: %+v", projected)
	}
	encode := func(items []normalized.Event) *bytes.Buffer {
		var output bytes.Buffer
		for _, item := range items {
			if err := json.NewEncoder(&output).Encode(item); err != nil {
				t.Fatal(err)
			}
		}
		return &output
	}
	original, err := Analyze(encode(events), Options{Window: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := Analyze(encode(projected), Options{Window: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, compact) {
		t.Fatalf("risk feature projection changed evidence\noriginal=%+v\ncompact=%+v", original, compact)
	}
}

func TestPlainPacketNDPHasNoGenericRiskEvidence(t *testing.T) {
	ndp := normalized.Event{
		EventID: "ndp-1", Timestamp: "2026-11-17T02:00:00Z", Type: "device",
		Source: "packet-sidecar", SourceEventType: "ndp",
		Subject: map[string]any{"campus_id": "site", "entity_role": "endpoint", "ip": "fe80::1234", "mac": "02:00:00:00:00:34"},
		Payload: map[string]any{"access_domain": "bond0", "message": "neighbor_advertisement", "origin": "ndp", "target": "fe80::abcd"},
		Flow:    map[string]any{"direction": "inbound", "dst_ip": "fe80::abcd", "proto": "ndp", "src_ip": "fe80::1234"},
	}
	encoded, err := json.Marshal(ndp)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Analyze(bytes.NewReader(append(encoded, '\n')), Options{Window: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 0 {
		t.Fatalf("plain NDP created generic risk evidence: %+v", result.Evidence)
	}
	if StreamRiskFeatureEligible(ndp) {
		t.Fatal("plain NDP scheduled generic risk despite having no risk signal")
	}
	for name, mutate := range map[string]func(*normalized.Event){
		"account":    func(event *normalized.Event) { event.Subject["account_id"] = "account-a" },
		"risk_field": func(event *normalized.Event) { event.Payload["user_agent"] = "Example" },
		"correction": func(event *normalized.Event) { event.Payload["revision"] = 2 },
		"withdrawal": func(event *normalized.Event) { event.Payload["withdrawn"] = true },
		"raw_ref":    func(event *normalized.Event) { event.RawRef = map[string]any{"corrects": "prior"} },
		"source":     func(event *normalized.Event) { event.Source = "device-signals" },
		"protocol":   func(event *normalized.Event) { event.SourceEventType = "ttl" },
	} {
		changed := ndp
		changed.Subject = cloneFeatureTestMap(ndp.Subject)
		changed.Payload = cloneFeatureTestMap(ndp.Payload)
		changed.Flow = cloneFeatureTestMap(ndp.Flow)
		mutate(&changed)
		if !StreamRiskFeatureEligible(changed) {
			t.Errorf("%s NDP expansion was silently removed from generic risk", name)
		}
	}
}

func cloneFeatureTestMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestAffectedSubjectWindowUsesFixedAsOf(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	events := []normalized.Event{
		{EventID: "old-a", Timestamp: now.Add(-11 * time.Minute).Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": "192.0.2.9"}, Payload: map[string]any{"ttl": 62}, Flow: map[string]any{"direction": "ingress"}},
		{EventID: "old-b", Timestamp: now.Add(-11*time.Minute + time.Second).Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": "192.0.2.9"}, Payload: map[string]any{"ttl": 126}, Flow: map[string]any{"direction": "ingress"}},
	}
	var lines bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&lines).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	result, err := Analyze(&lines, Options{Window: 10 * time.Minute, AsOf: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 0 {
		t.Fatalf("expired subject evidence returned during incremental recheck: %+v", result.Evidence)
	}
}
