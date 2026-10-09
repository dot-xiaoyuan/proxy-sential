package evidence

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestEvidenceObservationTimeIsolationReplay(t *testing.T) {
	base := time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC)
	event := func(id, kind, ip string, minute int, subject, payload map[string]any) normalized.Event {
		if subject == nil {
			subject = map[string]any{}
		}
		subject["ip"] = ip
		return normalized.Event{SchemaVersion: "v1", EventID: id, Type: kind, Timestamp: base.Add(time.Duration(minute) * time.Minute).Format(time.RFC3339Nano), Subject: subject, Payload: payload}
	}
	events := []normalized.Event{
		event("old-rule", "alert", "192.0.2.1", 0, nil, map[string]any{"signature": "ET POLICY OpenVPN Client Connection", "metadata": []string{"proxy_sentinel_confidence high", "source proxy-sentinel"}}),
		event("mac-1", "identity", "192.0.2.2", 1, map[string]any{"account_id": "fixture-account", "mac": "aa:bb:cc:dd:ee:01", "entity_role": "endpoint"}, nil),
		event("mac-2", "identity", "192.0.2.2", 2, map[string]any{"account_id": "fixture-account", "mac": "aa:bb:cc:dd:ee:02", "entity_role": "endpoint"}, nil),
		event("same-ip-normal", "flow", "192.0.2.1", 8, nil, nil),
		event("same-account-normal", "flow", "192.0.2.2", 8, map[string]any{"account_id": "fixture-account", "entity_role": "endpoint"}, nil),
		event("other-ip-normal", "dns", "192.0.2.3", 9, nil, map[string]any{"query": "normal.example.test"}),
	}
	for _, reverse := range []bool{false, true} {
		var input bytes.Buffer
		enc := json.NewEncoder(&input)
		for n := range events {
			index := n
			if reverse {
				index = len(events) - n - 1
			}
			if err := enc.Encode(events[index]); err != nil {
				t.Fatal(err)
			}
		}
		result, err := Analyze(&input, Options{Window: 10 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, item := range result.Evidence {
			want := base
			switch item.Type {
			case "vpn_proxy_rule_match":
			case "account_concurrent_macs":
				want = base.Add(2 * time.Minute)
			default:
				continue
			}
			found[item.Type] = true
			observed, err := time.Parse(time.RFC3339Nano, item.CreatedAt)
			if err != nil || !observed.Equal(want) {
				t.Errorf("unrelated traffic renewed %s evidence: reverse=%t got=%s want=%s", item.Type, reverse, item.CreatedAt, want.Format(time.RFC3339Nano))
			}
			key := item.IP
			if item.SubjectType != "ip" {
				key = item.SubjectType + ":" + item.SubjectID
			}
			if item.EvidenceID != evidenceID(key, item.Type, item.Window, want.Format(time.RFC3339Nano), item.Samples) {
				t.Error("unrelated batch watermark changed observation identity")
			}
		}
		if len(found) != 2 || result.MaxTime != base.Add(9*time.Minute).Format(time.RFC3339Nano) {
			t.Fatal("signal or batch watermark lost", found, result.MaxTime)
		}
	}
}
