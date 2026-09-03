package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClickHouseDomainEventCursorQueryIsBounded(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		query = string(data)
		_, _ = w.Write([]byte(`{"event_timestamp":"2026-09-02T10:00:00.000000Z","event_id":"domain-1","schema_version":"v1","source":"suricata","source_event_type":"tls","type":"tls","subject_ip":"192.0.2.10","endpoint_id":"endpoint-1","auth_session_id":"session-1","payload_json":"{\"sni\":\"push.apple.com\"}","flow_json":"{}"}` + "\n"))
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.ListDomainEventsAfter(context.Background(), "sensor-campus-a", "2026-09-01T00:00:00Z", "2026-09-02T09:00:00Z", "cursor-1", 50000)
	if err != nil || len(events) != 1 || events[0].Subject["endpoint_id"] != "endpoint-1" || events[0].Payload["session_id"] != "session-1" {
		t.Fatalf("unexpected cursor result: %+v err=%v", events, err)
	}
	for _, required := range []string{"type IN ('dns','tls','quic','http')", "sensor_id='sensor-campus-a'", "(timestamp,event_id) >", "LIMIT 10000"} {
		if !strings.Contains(query, required) {
			t.Fatalf("query is not bounded/cursor based; missing %q: %s", required, query)
		}
	}
}

func TestClickHouseDomainObservationWriteIncludesUnattributedMatches(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		_, _ = w.Write([]byte("{}\n"))
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = store.WriteDomainEcosystemObservations(context.Background(), []DomainEcosystemObservation{{DomainObservation: DomainObservation{EventID: "event-unattributed", Timestamp: "2026-09-02T10:00:00Z", Domain: "push.apple.example", EventSource: "tls", SensorID: "campus-a"}, Ecosystem: "Apple", Category: "push", RuleSource: "NextDNS", RuleVersion: "bundle-v2", Confidence: .55}})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"INSERT INTO domain_ecosystem_observations", `"event_id":"event-unattributed"`, `"attributed":false`, `"ecosystem":"Apple"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in domain observation insert: %s", expected, body)
		}
	}
}
