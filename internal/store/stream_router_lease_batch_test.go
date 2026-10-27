package store

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
)

func TestStreamRouterLeaseBatchPreservesEventTimeAndConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := "2026-10-27T02:00:00Z"
	events := []normalized.Event{
		{Timestamp: at, Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"campus_id": "campus-a", "ip": "192.0.2.1"}},
		{Timestamp: at, Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"campus_id": "campus-a", "ip": "192.0.2.1"}},
		{Timestamp: at, Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"campus_id": "campus-a", "ip": "192.0.2.2"}},
		{Timestamp: at, Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"campus_id": "campus-a", "ip": "192.0.2.3", "mac": "02:00:00:00:00:03"}},
	}
	mock.ExpectQuery("WITH request AS").WithArgs(sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"ordinal", "endpoint_id"}).
			AddRow(1, "mac:02:00:00:00:00:01").
			AddRow(1, "mac:02:00:00:00:00:02").
			AddRow(2, nil),
	)
	got, err := (&PostgresStore{db: db}).resolveRouterLeaseBatch(context.Background(), events)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two unique address/time lookups, got %d", len(got))
	}
	first := got[routerLeaseKeyFromEvent(events[0])]
	if first.EndpointID != "mac:02:00:00:00:00:01" || first.MAC != "02:00:00:00:00:01" || !first.Ambiguous || first.Quality != "dhcp_lease" {
		t.Fatalf("conflicting lease changed attribution: %+v", first)
	}
	if got[routerLeaseKeyFromEvent(events[2])].EndpointID != "" {
		t.Fatalf("unmatched lease became a current device: %+v", got[routerLeaseKeyFromEvent(events[2])])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRouterWeakOnlyBatchDoesNotWriteUnchangedProjection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := normalized.Event{
		SchemaVersion: "v1", EventID: "ttl-only", Timestamp: "2026-10-27T02:00:00Z",
		Type: "device", Source: "packet-sidecar", SourceEventType: "ttl",
		Observer: map[string]any{"sensor_id": "sensor-a"},
		Subject:  map[string]any{"ip": "192.0.2.1", "mac": "02:00:00:00:00:01"},
		Flow:     map[string]any{"ttl": 64},
	}
	if err := (&DBStore{pg: &PostgresStore{db: db}}).analyzeAndWriteRouterEvents(context.Background(), []normalized.Event{event}); err != nil {
		t.Fatalf("weak-only observation should not rewrite the router rule/projection: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRouterPurePacketTTLBatchNeedsNoLeaseRead(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := normalized.Event{
		SchemaVersion: "v1", EventID: "ttl-only", Timestamp: "2026-10-27T02:00:00Z",
		Type: "device", Source: "packet-sidecar", SourceEventType: "ttl",
		Observer: map[string]any{"sensor_id": "sensor-a"},
		Subject:  map[string]any{"ip": "192.0.2.1"},
		Payload:  map[string]any{"origin": "ttl", "neighbor_mac": "02:00:00:00:00:01", "neighbor_role": "unverified", "ttl": 64},
		Flow:     map[string]any{"src_ip": "192.0.2.1", "direction": "egress", "ip_version": 4, "traffic_scope": "campus"},
	}
	batch := make([]normalized.Event, 100)
	for index := range batch {
		batch[index] = event
	}
	if err := (&DBStore{pg: &PostgresStore{db: db}}).analyzeAndWriteStreamRouterEvents(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	event.Payload["hostname"] = "router.example"
	if isPurePacketRouterTTL(event) {
		t.Fatal("TTL event with router fingerprint must be analyzed")
	}
}

func TestStreamRouterMixedBatchKeepsRouterEvidenceWithoutPureTTL(t *testing.T) {
	weak := normalized.Event{
		Type: "device", Source: "packet-sidecar", SourceEventType: "ttl",
		Subject: map[string]any{"ip": "192.0.2.1"},
		Payload: map[string]any{"origin": "ttl", "neighbor_role": "unverified", "ttl": 64},
		Flow:    map[string]any{"src_ip": "192.0.2.1", "traffic_scope": "campus"},
	}
	strong := normalized.Event{
		Type: "router", Source: "zeek", SourceEventType: "lldp",
		Subject: map[string]any{"ip": "192.0.2.2"},
		Payload: map[string]any{"capabilities": "Router"},
	}
	got, excluded := routerScoringEvents([]normalized.Event{weak, strong})
	if excluded != 1 || len(got) != 1 || got[0].SourceEventType != "lldp" {
		t.Fatalf("mixed stream must retain router evidence while excluding pure TTL: excluded=%d events=%+v", excluded, got)
	}
}
