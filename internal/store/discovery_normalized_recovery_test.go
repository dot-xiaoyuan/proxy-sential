package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
)

func TestDiscoveryCompensationBoundsLookupAndChecksContent(t *testing.T) {
	event := probeEvent("discovery-recovery")
	event.Subject = map[string]any{"ip": "192.0.2.10"}
	event.Timestamp = "2026-10-23T01:02:03.123456789Z"
	row := map[string]any{"event_id": event.EventID, "schema_version": event.SchemaVersion, "source": event.Source, "source_event_type": event.SourceEventType, "type": event.Type, "event_timestamp": "2026-10-23T01:02:03.123456Z", "observer_json": jsonString(event.Observer), "subject_json": jsonString(event.Subject), "payload_json": jsonString(event.Payload), "flow_json": jsonString(event.Flow), "raw_ref_json": jsonString(event.RawRef), "confidence": event.Confidence}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := string(b)
		for _, fragment := range []string{"sensor_id='sensor-a'", "subject_ip='192.0.2.10'", "timestamp>=", "timestamp<=", "event_id IN"} {
			if !strings.Contains(q, fragment) {
				t.Errorf("unbounded lookup missing %s", fragment)
			}
		}
		_ = json.NewEncoder(w).Encode(row)
	}))
	defer server.Close()
	ch, _ := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	found, err := ch.existingDiscoveryEvents(context.Background(), []normalized.Event{event})
	if err != nil || !found[discoveryEventKey(event)] {
		t.Fatalf("lookup %v %v", found, err)
	}
	event.Subject = map[string]any{"ip": "192.0.2.10", "name": "different"}
	if _, err = ch.existingDiscoveryEvents(context.Background(), []normalized.Event{event}); err == nil {
		t.Fatal("conflicting content accepted")
	}
}

func TestDiscoveryCompensationUsesOneQueryForFiftyAddresses(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if strings.Count(string(b), "subject_ip=") != 50 {
			t.Errorf("missing bounded address predicates")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ch, _ := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	events := []normalized.Event{}
	for n := 0; n < 50; n++ {
		e := probeEvent(fmt.Sprintf("event-%d", n))
		e.Subject = map[string]any{"ip": fmt.Sprintf("192.0.2.%d", n+1)}
		events = append(events, e)
	}
	if _, err := ch.existingDiscoveryEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("%d round trips for one segment", calls)
	}
}

func TestDiscoveryRecoveryKeyIncludesRevisionAndSource(t *testing.T) {
	a := probeEvent("same")
	b := a
	b.Observer = map[string]any{"sensor_id": "sensor-a", "source_id": "another"}
	if discoveryEventKey(a) == discoveryEventKey(b) {
		t.Fatal("source identities collapsed")
	}
	b = a
	b.Payload = map[string]any{"revision": 1}
	if discoveryEventKey(a) == discoveryEventKey(b) {
		t.Fatal("revision collapsed")
	}
	if _, err := discoveryComparableEvent(normalized.Event{Timestamp: "bad"}); err == nil {
		t.Fatal("invalid timestamp accepted")
	}
}
