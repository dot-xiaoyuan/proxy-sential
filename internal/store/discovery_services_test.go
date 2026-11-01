package store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryServiceClueQueryScopesMACToSensorAndKeepsEvidence(t *testing.T) {
	query, requested := discoveryServiceCluesQuery([]string{
		"sensor-a|00:11:22:33:44:55|192.0.2.10",
		"sensor-a|00:11:22:33:44:55|192.0.2.10",
		"sensor-b|00:11:22:33:44:66|192.0.2.11",
		"sensor-a|00:11:22:33:44:55|invalid-ip",
		"bad' OR 1=1|00:11:22:33:44:77|192.0.2.12",
	}, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if len(requested) != 2 || !requested["sensor-a|00:11:22:33:44:55|192.0.2.10"] || !requested["sensor-b|00:11:22:33:44:66|192.0.2.11"] {
		t.Fatalf("unexpected requested pairs: %#v", requested)
	}
	for _, want := range []string{"(sensor_id,subject_ip) IN (('sensor-a','192.0.2.10'),('sensor-b','192.0.2.11'))", "'00:11:22:33:44:55'", "subject_ip AS source_ip", "source_event_type='dns_sd'", "argMax(event_id,timestamp) AS evidence_id"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query missing %q: %s", want, query)
		}
	}
	if strings.Contains(query, "WHERE source_event_type='dns_sd'") || !strings.Contains(query, "AND source_event_type='dns_sd'\nWHERE") {
		t.Fatalf("event type must filter before reading DNS-SD payload: %s", query)
	}
	if strings.Contains(query, "OR 1=1") || strings.Contains(query, "src_ip AS source_ip") {
		t.Fatal("untrusted sensor reached SQL")
	}
	if query, _ := discoveryServiceCluesQuery([]string{"sensor-a|00:11:22:33:44:55"}, time.Time{}); query != "" {
		t.Fatal("address-free request must not scan the raw event window")
	}
}

func TestDiscoveryServiceCluesRejectsAnotherAddressOnSameMAC(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sensor_id":"sensor-a","mac":"00:11:22:33:44:55","source_ip":"192.0.2.10","service_type":"_ipp._tcp","port":631,"last_seen":"2026-11-01 00:00:00","evidence_id":"event-a"}
{"sensor_id":"sensor-a","mac":"00:11:22:33:44:55","source_ip":"192.0.2.11","service_type":"_ipp._tcp","port":631,"last_seen":"2026-11-01 00:00:00","evidence_id":"event-b"}
`))
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.DiscoveryServiceClues(context.Background(), []string{"sensor-a|00:11:22:33:44:55|192.0.2.10"}, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	clues := got["sensor-a|00:11:22:33:44:55"]
	if len(clues) != 1 || clues[0].SourceIP != "192.0.2.10" || clues[0].EvidenceID != "event-a" {
		t.Fatalf("unexpected service clues: %#v", clues)
	}
}
