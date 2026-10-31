package store

import (
	"strings"
	"testing"
	"time"
)

func TestDiscoveryServiceClueQueryScopesMACToSensorAndKeepsEvidence(t *testing.T) {
	query, requested := discoveryServiceCluesQuery([]string{
		"sensor-a|00:11:22:33:44:55",
		"sensor-a|00:11:22:33:44:55",
		"sensor-b|00:11:22:33:44:66",
		"bad' OR 1=1|00:11:22:33:44:77",
	}, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if len(requested) != 2 || !requested["sensor-a|00:11:22:33:44:55"] || !requested["sensor-b|00:11:22:33:44:66"] {
		t.Fatalf("unexpected requested pairs: %#v", requested)
	}
	for _, want := range []string{"sensor_id IN ('sensor-a','sensor-b')", "'00:11:22:33:44:55'", "src_ip AS source_ip", "argMax(event_id,timestamp) AS evidence_id"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query missing %q: %s", want, query)
		}
	}
	if strings.Contains(query, "OR 1=1") {
		t.Fatal("untrusted sensor reached SQL")
	}
}
