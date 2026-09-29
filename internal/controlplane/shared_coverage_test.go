package controlplane

import (
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/sharedaccess"
	"testing"
	"time"
)

func TestSharedCoverageRequiresFreshMeasuredWindow(t *testing.T) {
	now := time.Now().UTC()
	w := sharedaccess.Window{SensorID: "capture", CampusID: "office", AccessDomain: "lan", Sources: []string{"suricata"}, From: now.Add(-30 * time.Second), To: now}
	d := ingest.Diagnostic{DiagnosticID: "heartbeat", Timestamp: now.Format(time.RFC3339Nano), SensorID: "capture", Collector: ingest.Collector{Kind: "suricata"}, Stage: "capture_health", Type: "capture_coverage", Details: map[string]any{"schema_version": "capture-coverage/v1", "campus_id": "office", "access_domain": "lan", "covered_from": w.From, "covered_to": w.To, "complete": true, "stopped": false, "query_truncated": false, "dropped_packets": int64(0)}}
	for _, test := range []struct {
		name, key string
		value     any
		want      string
	}{
		{"healthy", "", nil, ""}, {"stopped", "stopped", true, "capture_stopped"}, {"drop", "dropped_packets", 1, "capture_packets_dropped"}, {"truncated", "query_truncated", true, "capture_query_truncated"}, {"incomplete", "complete", false, "capture_coverage_incomplete"}, {"heartbeat-only", "covered_from", now, "capture_window_not_covered"}, {"missing", "dropped_packets", nil, "capture_health_fields_missing"}, {"scope", "access_domain", "other", "capture_coverage_not_verified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := d
			copy.Details = map[string]any{}
			for k, v := range d.Details {
				copy.Details[k] = v
			}
			if test.key != "" {
				copy.Details[test.key] = test.value
			}
			got := coverageBlockers(w, []ingest.Diagnostic{copy}, now)
			if test.want == "" && len(got) != 0 || test.want != "" && (len(got) != 1 || got[0] != test.want) {
				t.Fatal(got)
			}
		})
	}
	if got := coverageBlockers(w, nil, now); len(got) != 1 || got[0] != "capture_coverage_not_verified" {
		t.Fatal(got)
	}
	if got := coverageBlockers(w, []ingest.Diagnostic{d}, now.Add(6*time.Second)); len(got) != 1 || got[0] != "capture_heartbeat_stale" {
		t.Fatal(got)
	}
	stopped := d
	stopped.DiagnosticID = "new-stopped"
	stopped.Timestamp = now.Add(time.Second).Format(time.RFC3339Nano)
	stopped.Details = map[string]any{}
	for k, v := range d.Details {
		stopped.Details[k] = v
	}
	stopped.Details["stopped"] = true
	if got := coverageBlockers(w, []ingest.Diagnostic{d, stopped}, now.Add(time.Second)); len(got) != 1 || got[0] != "capture_stopped" {
		t.Fatal(got)
	}
	malformed := stopped
	malformed.Details = map[string]any{}
	for k, v := range d.Details {
		malformed.Details[k] = v
	}
	malformed.Details["dropped_packets"] = "not-a-number"
	if got := coverageBlockers(w, []ingest.Diagnostic{d, malformed}, now.Add(time.Second)); len(got) != 1 || got[0] != "capture_health_fields_missing" {
		t.Fatal("malformed latest health reused an older healthy record", got)
	}

}
