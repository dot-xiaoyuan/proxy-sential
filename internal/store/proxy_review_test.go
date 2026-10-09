package store

import (
	"testing"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func TestBuildProxyReviewResponseAggregatesIdentityDestinationAndRules(t *testing.T) {
	events := []normalized.Event{
		proxyTestEvent("identity-1", "identity", "2026-08-20T10:00:00Z", map[string]any{
			"ip": "10.0.0.8", "account_id": "account-1", "endpoint_id": "endpoint-1", "access_id": "Dorm-A-AP01", "entity_role": "endpoint",
		}, map[string]any{}, map[string]any{}),
		proxyTestEvent("tls-1", "tls", "2026-08-20T10:05:00Z", map[string]any{"ip": "10.0.0.8"},
			map[string]any{"dst_ip": "198.51.100.8", "dst_port": 443, "proto": "tcp", "start": "2026-08-20T10:04:00Z", "end": "2026-08-20T10:06:00Z"},
			map[string]any{"sni": "student-vpn.example.test", "ja3": "ja3-a"}),
		proxyTestEvent("alert-1", "alert", "2026-08-20T10:07:00Z", map[string]any{"ip": "10.0.0.8"},
			map[string]any{"dst_ip": "198.51.100.8", "dst_port": 1194, "proto": "udp"},
			map[string]any{"signature": "ET POLICY OpenVPN Client Connection", "category": "Privacy Violation", "action": "allowed", "severity": 2}),
	}
	risks := ProxyReviewRiskMap([]risk.Snapshot{{
		IP: "10.0.0.8", SubjectType: "ip", SubjectID: "10.0.0.8", Score: 88, Level: "confirmed",
		EvidenceIDs: []string{"evidence-vpn"}, ReviewStatus: "needs_more_data", ReviewReason: "等待终端核验",
	}})

	result := BuildProxyReviewResponse("office-30", "7d", events, risks)
	if result.CaseCount != 1 || result.AccountCount != 1 || result.EndpointCount != 1 || result.HighConfidenceCount != 0 {
		t.Fatalf("unexpected overview: %+v", result)
	}
	item := result.Items[0]
	if item.AccountID != "account-1" || item.EndpointID != "endpoint-1" || len(item.AccessIDs) != 1 || item.AccessIDs[0] != "Dorm-A-AP01" {
		t.Fatalf("identity correlation failed: %+v", item)
	}
	if item.ConfidenceLevel != "medium" || item.AlertCount != 1 || len(item.RuleMatches) != 1 || item.RuleMatches[0].Signature == "" {
		t.Fatalf("rule aggregation failed: %+v", item)
	}
	if item.DurationSeconds != 180 || item.RiskScore != 88 || item.RiskLevel != "confirmed" || item.ReviewStatus != "needs_more_data" {
		t.Fatalf("duration/risk/review enrichment failed: %+v", item)
	}
	if len(item.Destinations) != 2 || len(item.DestinationIPs) != 2 || len(item.DestinationDomains) != 1 || len(item.TLSFingerprints) != 1 || len(item.EvidenceIDs) != 1 {
		t.Fatalf("destination/evidence aggregation failed: %+v", item)
	}
}

func TestBuildProxyReviewResponseKeepsOrdinaryQUICLowConfidence(t *testing.T) {
	events := []normalized.Event{
		proxyTestEvent("quic-1", "quic", "2026-08-20T10:00:00Z", map[string]any{"ip": "10.0.0.9"},
			map[string]any{"dst_ip": "203.0.113.9", "dst_port": 443, "proto": "udp", "start": "2026-08-20T09:00:00Z", "end": "2026-08-20T10:00:00Z"},
			map[string]any{"sni": "meeting.example.test", "alpn": "h3"}),
		proxyTestEvent("alert-benign", "alert", "2026-08-20T10:01:00Z", map[string]any{"ip": "10.0.0.9"},
			map[string]any{"dst_ip": "203.0.113.9", "dst_port": 443, "proto": "udp"},
			map[string]any{"signature": "ET INFO Video Conference Traffic"}),
	}

	result := BuildProxyReviewResponse("office-30", "7d", events, map[string]risk.Snapshot{})
	if result.CaseCount != 1 || result.EventCount != 1 || result.HighConfidenceCount != 0 {
		t.Fatalf("ordinary alert must not enter proxy review evidence: %+v", result)
	}
	item := result.Items[0]
	if item.ConfidenceLevel != "low" || item.AlertCount != 0 || len(item.RuleMatches) != 0 || item.DurationSeconds != 3600 {
		t.Fatalf("ordinary QUIC must remain low confidence: %+v", item)
	}
}

func TestBuildProxyReviewResponseUsesAggregateWeights(t *testing.T) {
	event := proxyTestEvent("tls-aggregate", "tls", "2026-08-20T10:00:00Z", map[string]any{"ip": "10.20.1.10"},
		map[string]any{"dst_ip": "198.51.100.1", "dst_port": 443, "proto": "tcp"},
		map[string]any{"sni": "vpn.example.test", "ja3": "aggregate-ja3", "_aggregate_count": 42})

	response := BuildProxyReviewResponse("sensor-a", "7d", []normalized.Event{event}, map[string]risk.Snapshot{})
	if response.EventCount != 42 || len(response.Items) != 1 || response.Items[0].EventCount != 42 || response.Items[0].TLSCount != 42 {
		t.Fatalf("expected aggregate event weight, got %+v", response)
	}
	if len(response.Items[0].DestinationDomains) != 1 || response.Items[0].DestinationDomains[0].Count != 42 {
		t.Fatalf("expected weighted domain count, got %+v", response.Items[0].DestinationDomains)
	}
	if len(response.Items[0].TLSFingerprints) != 1 || response.Items[0].TLSFingerprints[0].Count != 42 {
		t.Fatalf("expected weighted fingerprint count, got %+v", response.Items[0].TLSFingerprints)
	}
}

func TestDecodeProxyReviewEventRows(t *testing.T) {
	raw := `{"first_seen":"2026-08-20 10:00:00.000000","last_seen":"2026-08-20 10:10:00.000000","event_id":"event-1","type":"alert","subject_ip":"10.20.1.10","dst_ip":"198.51.100.1","dst_port":1194,"proto":"udp","sni":"vpn.example.test","server_name":"","host":"","query":"","ja3":"ja3-a","ja4":"","signature":"OpenVPN tunnel","category":"policy","action":"allowed","severity":2,"metadata_json":"{\"confidence\":\"high\"}","aggregate_count":7}` + "\n"
	events, err := decodeProxyReviewEventRows([]byte(raw), "sensor-a")
	if err != nil {
		t.Fatalf("decode aggregate rows: %v", err)
	}
	if len(events) != 1 || events[0].Timestamp != "2026-08-20T10:10:00+08:00" || intFromMap(events[0].Payload, "_aggregate_count") != 7 {
		t.Fatalf("unexpected aggregate event: %+v", events)
	}
	if stringFromMap(events[0].Flow, "dst_ip") != "198.51.100.1" || stringFromMap(events[0].Payload, "signature") != "OpenVPN tunnel" {
		t.Fatalf("missing aggregate fields: %+v", events[0])
	}
}

func proxyTestEvent(id, eventType, timestamp string, subject, flow, payload map[string]any) normalized.Event {
	return normalized.Event{
		SchemaVersion: "v1", EventID: id, Source: "test", Type: eventType, Timestamp: timestamp,
		Observer: map[string]any{"sensor_id": "office-30"}, Subject: subject, Flow: flow, Payload: payload, Confidence: 1,
	}
}
