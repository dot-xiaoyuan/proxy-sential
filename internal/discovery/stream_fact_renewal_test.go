package discovery

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestStreamFactRowMaterialIgnoresShortRenewalAndKeepsRealChanges(t *testing.T) {
	now := time.Date(2026, 11, 18, 7, 0, 0, 0, time.UTC)
	prior := streamDiscoveryFact{Scope: "scope-a", Protocol: "ndp", SemanticHash: "same", IP: "fe80::1", MAC: "02:00:00:00:00:01",
		FirstObserved: now.Add(-time.Hour), ValidUntil: now.Add(10 * time.Minute)}
	short := prior
	short.ValidUntil = prior.ValidUntil.Add(4*time.Minute + 59*time.Second)
	if streamFactRowMaterial(&prior, short) {
		t.Fatal("lease extension under five minutes rewrote the fact")
	}
	boundary := prior
	boundary.ValidUntil = prior.ValidUntil.Add(streamFactLeaseRefresh)
	if !streamFactRowMaterial(&prior, boundary) {
		t.Fatal("five-minute lease extension was dropped")
	}
	shorter := prior
	shorter.ValidUntil = prior.ValidUntil.Add(-time.Second)
	if !streamFactRowMaterial(&prior, shorter) {
		t.Fatal("shorter lease was dropped")
	}
	changed := prior
	changed.SemanticHash = "changed"
	withdrawn := prior
	withdrawn.Withdrawn = true
	earlier := prior
	earlier.FirstObserved = prior.FirstObserved.Add(-time.Second)
	rebound := prior
	rebound.AddressBinding = true
	for name, next := range map[string]streamDiscoveryFact{"hash": changed, "withdrawal": withdrawn, "earlier first": earlier, "binding": rebound} {
		if !streamFactRowMaterial(&prior, next) {
			t.Fatalf("%s was treated as a pure renewal", name)
		}
	}
	late := prior
	late.Observed = now.Add(-time.Hour)
	if decision := mergeStreamDiscoveryFact(&prior, late); decision.WriteFact {
		t.Fatal("late observation was written over the current fact")
	}
	gateway := prior
	gateway.DeviceType = "gateway"
	gateway.ValidUntil = prior.ValidUntil.Add(time.Second)
	if !streamFactRowMaterial(&prior, gateway) {
		t.Fatal("gateway lease extension was treated as an ordinary heartbeat")
	}
}

func TestStreamFactUpsertKeepsShortRenewalOffTheConflictUpdate(t *testing.T) {
	source, err := os.ReadFile("stream_projection_db.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(source)
	for _, required := range []string{
		"stream_discovery_facts.semantic_hash IS DISTINCT FROM EXCLUDED.semantic_hash",
		"stream_discovery_facts.address_binding IS DISTINCT FROM EXCLUDED.address_binding",
		"stream_discovery_facts.withdrawn IS DISTINCT FROM EXCLUDED.withdrawn",
		"stream_discovery_facts.ip IS DISTINCT FROM EXCLUDED.ip",
		"stream_discovery_facts.mac IS DISTINCT FROM EXCLUDED.mac",
		"EXCLUDED.valid_until<stream_discovery_facts.valid_until",
		"EXCLUDED.valid_until>=stream_discovery_facts.valid_until+interval '5 minutes'",
		"EXCLUDED.device_type IN ('router','gateway','access_point','switch','firewall')",
	} {
		if !strings.Contains(code, required) {
			t.Fatalf("fact upsert lost %s", required)
		}
	}
}

func TestStreamShortNDPRenewalKeepsReceiptWithoutFactOrDeviceWrite(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	event := sidecarNDPEvent("ndp-repeat", now.Format(time.RFC3339Nano), "neighbor_advertisement", "fe80::abcd", 600)
	event.Source = "passive"
	segment := streamlog.Segment{Epoch: "epoch-a", Source: "device-signals", SourcePath: "packet://ttl",
		AcceptedAt: now, ArchiveMonth: now.Format("200601"), Events: []normalized.Event{event}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || !prepared[0].HasFact {
		t.Fatalf("prepare NDP: %v", err)
	}
	next := prepared[0].Fact
	prior := next
	prior.Event = "epoch-a:ndp-before"
	prior.EvidenceEvent = prior.Event
	prior.Observed = now.Add(-time.Minute)
	prior.FirstObserved = now.Add(-time.Hour)
	prior.ValidUntil = next.ValidUntil.Add(-time.Minute)
	recognitionRaw, _ := json.Marshal(prior.RecognitionFields)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO stream_projection_segments`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO stream_discovery_event_keys`).WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(hashtextextended`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT f.device_key,f.fact_key,f.scope_id`).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "fact_key", "scope_id", "event_key", "visible_event_key", "revision", "first_observed_at", "observed_at", "valid_until", "withdrawn", "semantic_hash", "mac", "recognition_fields", "ip", "sensor_id", "site", "domain", "vlan", "vrf", "interface_name", "protocol", "address_binding"}).
			AddRow(prior.Device, prior.Key, prior.Scope, prior.Event, prior.EvidenceEvent, prior.Revision, prior.FirstObserved, prior.Observed, prior.ValidUntil, prior.Withdrawn, prior.SemanticHash, prior.MAC, recognitionRaw,
				prior.IP, prior.Sensor, prior.Site, prior.Domain, prior.VLAN, prior.VRF, prior.Interface, prior.Protocol, prior.AddressBinding))
	mock.ExpectExec(`WITH inputs AS MATERIALIZED`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "ndp-short", segment); err != nil {
		t.Fatalf("short NDP renewal did not commit the receipt: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamGatewayRenewalStillPublishesNetworkState(t *testing.T) {
	now := time.Date(2026, 11, 18, 7, 30, 0, 0, time.UTC)
	event := normalized.Event{SchemaVersion: "v1", EventID: "ssdp-renew", Source: "packet-sidecar", SourceEventType: "ssdp", Type: "device", Timestamp: now.Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a", "interface": "bond0"},
		Subject:  map[string]any{"campus_id": "site-a", "ip": "10.2.3.4"},
		Payload:  map[string]any{"access_domain": "bond0", "nt": "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "usn": "uuid:router::urn:schemas-upnp-org:device:InternetGatewayDevice:1", "ttl": 600}}
	segment := streamlog.Segment{Epoch: "epoch-a", Source: "device-signals", SourcePath: "packet://ttl",
		AcceptedAt: now, ArchiveMonth: now.Format("200601"), Events: []normalized.Event{event}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].Fact.DeviceType != "gateway" {
		t.Fatalf("prepare gateway: %+v %v", prepared, err)
	}
	next := prepared[0].Fact
	prior := next
	prior.Event = "epoch-a:ssdp-before"
	prior.EvidenceEvent = prior.Event
	prior.Observed = now.Add(-time.Minute)
	prior.FirstObserved = now.Add(-time.Hour)
	prior.ValidUntil = next.ValidUntil.Add(-time.Minute)
	recognitionRaw, _ := json.Marshal(prior.RecognitionFields)
	factRaw, _ := json.Marshal(next)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO stream_projection_segments`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO stream_discovery_event_keys`).WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(hashtextextended`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT f.device_key,f.fact_key,f.scope_id`).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "fact_key", "scope_id", "event_key", "visible_event_key", "revision", "first_observed_at", "observed_at", "valid_until", "withdrawn", "semantic_hash", "mac", "recognition_fields", "ip", "sensor_id", "site", "domain", "vlan", "vrf", "interface_name", "protocol", "address_binding"}).
			AddRow(prior.Device, prior.Key, prior.Scope, prior.Event, prior.EvidenceEvent, prior.Revision, prior.FirstObserved, prior.Observed, prior.ValidUntil, prior.Withdrawn, prior.SemanticHash, prior.MAC, recognitionRaw,
				prior.IP, prior.Sensor, prior.Site, prior.Domain, prior.VLAN, prior.VRF, prior.Interface, prior.Protocol, prior.AddressBinding))
	mock.ExpectExec(`INSERT INTO stream_discovery_facts`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`WITH inputs AS MATERIALIZED`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM stream_discovery_device_state WHERE epoch=`).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}))
	mock.ExpectQuery(`JOIN LATERAL`).WillReturnRows(sqlmock.NewRows([]string{"device_key", "fact"}).AddRow(next.Device, factRaw))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(9184,213\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_discovery_device_state`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_discovery_network_state`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "gateway-renew", segment); err != nil {
		t.Fatalf("gateway renewal was not published: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
