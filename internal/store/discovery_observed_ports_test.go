package store

import (
	"strings"
	"testing"
	"time"
)

func TestDiscoveryObservedFlowQueryKeepsSensorIPAndBucketBounds(t *testing.T) {
	query := discoveryObservedFlowPortsQuery(
		[]string{"sensor-a|192.0.2.10", "sensor-a|192.0.2.10", "bad' OR 1=1|192.0.2.10", "sensor-a|192.0.2.10' OR 1=1"},
		time.Date(2026, 11, 1, 0, 13, 0, 0, time.UTC),
	)
	for _, want := range []string{"(sensor_id,src_ip) IN (('sensor-a','192.0.2.10'))", "2026-11-01 00:10:00", "discovery_observed_flow_ports_10m", "argMaxMerge(evidence_id)", "proto AS observation_proto", "countIf(observation_proto='tcp_synack')", "argMaxIf(observed_evidence,observed_last,observation_proto='tcp_synack')", "LIMIT 8 BY sensor_id,src_ip"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query missing %q: %s", want, query)
		}
	}
	if strings.Contains(query, "OR 1=1") || strings.Contains(query, "normalized_events") {
		t.Fatalf("unsafe or raw-window query: %s", query)
	}
	if discoveryObservedFlowPortsQuery([]string{"|192.0.2.10"}, time.Time{}) != "" {
		t.Fatal("query without sensor must not scan flow buckets")
	}
}
