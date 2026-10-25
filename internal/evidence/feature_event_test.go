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
