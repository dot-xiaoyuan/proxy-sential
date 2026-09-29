package store

import (
	"context"
	"os"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func leaseEvent(id, mac, at, action string) normalized.Event {
	return normalized.Event{SchemaVersion: "v1", EventID: id, Type: "device", Source: "zeek", SourceEventType: "dhcp", Timestamp: at, Observer: map[string]any{"sensor_id": "lease-test"}, Subject: map[string]any{"ip": "192.0.2.192", "mac": mac}, Payload: map[string]any{"origin": "dhcp", "assigned_addr": "192.0.2.192", "msg_types": action, "lease_time": "600", "lease_observed_at": at}, Confidence: .9}
}
func TestDeviceLeaseRequiresAcknowledgement(t *testing.T) {
	for _, action := range []string{"REQUEST", "OFFER", "INFORM", ""} {
		e := leaseEvent("x", "02:00:00:00:09:01", "2026-09-16T00:00:00Z", action)
		if _, ok := deviceLeaseFromEvent(e); ok {
			t.Fatalf("accepted %s", action)
		}
	}
	e := leaseEvent("x", "02:00:00:00:09:01", "2026-09-16T00:00:00Z", "REQUEST,ACK")
	if l, ok := deviceLeaseFromEvent(e); !ok || !l.Until.Equal(time.Date(2026, 9, 16, 0, 10, 0, 0, time.UTC)) {
		t.Fatalf("lease %+v %v", l, ok)
	}
	e.Payload["lease_time"] = "NaN"
	if _, ok := deviceLeaseFromEvent(e); ok {
		t.Fatal("invalid duration accepted")
	}
}
func TestPostgresDeviceLeaseAttribution(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated postgres required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.db.ExecContext(ctx, "DELETE FROM device_address_leases WHERE sensor_id='lease-test'")
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.ExecContext(ctx, "DELETE FROM device_address_leases WHERE sensor_id='lease-test'")
	a := leaseEvent("lease-a", "02:00:00:00:09:01", "2026-09-16T00:00:00Z", "ACK")
	a.Payload["hostname"] = "iPhone"
	b := leaseEvent("lease-b", "02:00:00:00:09:02", "2026-09-16T00:05:00Z", "ACK")
	// Reverse order and duplicate input must have identical event-time ownership.
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{b, a, a}); err != nil {
		t.Fatal(err)
	}
	check := func(at, sensor, want string, conflict bool) {
		t.Helper()
		r, ok, e := s.ResolveDeviceAt(ctx, DomainObservation{IP: "192.0.2.192", Timestamp: at, SensorID: sensor})
		if e != nil || (want != "" && (!ok || r.EndpointID != want)) || (want == "" && ok) || r.Conflict != conflict {
			t.Fatalf("%s/%s got %+v ok=%v err=%v", at, sensor, r, ok, e)
		}
	}
	// A later sparse observation must not erase previously collected hostname evidence.
	sparse := a
	sparse.EventID = "lease-a-sparse"
	sparse.Payload = map[string]any{"origin": "dhcp"}
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{sparse}); err != nil {
		t.Fatal(err)
	}
	var brand string
	if err = s.db.QueryRowContext(ctx, `SELECT brand FROM endpoint_device_profiles WHERE endpoint_id='mac:02:00:00:00:09:01'`).Scan(&brand); err != nil || brand != "Apple" {
		t.Fatalf("merged profile lost: %q %v", brand, err)
	}
	check("2026-09-16T00:04:00Z", "lease-test", "mac:02:00:00:00:09:01", false)
	check("2026-09-16T00:06:00Z", "lease-test", "mac:02:00:00:00:09:02", false)
	check("2026-09-16T00:06:00Z", "other", "", false)
	otherScope, found, err := s.ResolveDeviceAt(ctx, DomainObservation{IP: "192.0.2.192", Timestamp: "2026-09-16T00:06:00Z", SensorID: "lease-test", CampusID: "other"})
	if err != nil || found || otherScope.EndpointID != "" {
		t.Fatalf("cross-campus lease %+v %v", otherScope, err)
	}
	check("2026-09-15T23:59:59Z", "lease-test", "", false)

	check("2026-09-16T00:15:00Z", "lease-test", "", false)
	lib, err := fingerprint.LoadDomainLibrary("lease-replay", []byte(`[{"domain":"push.apple.test","match_type":"exact","ecosystem":"Apple","category":"push","confidence":0.55,"source":"test"}]`))
	if err != nil {
		t.Fatal(err)
	}
	ev := normalized.Event{EventID: "lease-domain-replay", Type: "tls", Timestamp: "2026-09-16T00:06:00Z", Observer: map[string]any{"sensor_id": "lease-test"}, Subject: map[string]any{"ip": "192.0.2.192"}, Payload: map[string]any{"sni": "push.apple.test"}}
	for range 2 {
		r, err := s.ProcessDomainEvents(ctx, []normalized.Event{ev}, lib)
		if err != nil || r.Attributed != 1 || r.Observations[0].EndpointID != "mac:02:00:00:00:09:02" || r.Observations[0].AttributionMethod != "dhcp_lease" {
			t.Fatalf("domain attribution %+v err=%v", r, err)
		}
	}
	var count int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_domain_evidence_events WHERE rule_version='lease-replay' AND event_id='lease-domain-replay'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate domain evidence: %d %v", count, err)
	}
	ev.Observer["sensor_id"] = "other"
	r, err := s.ProcessDomainEvents(ctx, []normalized.Event{ev}, lib)
	if err != nil || r.Attributed != 0 {
		t.Fatalf("cross-sensor attribution %+v %v", r, err)
	}
	stop := leaseEvent("lease-stop", "02:00:00:00:09:02", "2026-09-16T00:07:00Z", "RELEASE")
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{stop}); err != nil {
		t.Fatal(err)
	}
	check("2026-09-16T00:08:00Z", "lease-test", "", false)
	c := leaseEvent("lease-c", "02:00:00:00:09:03", "2026-09-16T00:05:00Z", "ACK")
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{c}); err != nil {
		t.Fatal(err)
	}
	check("2026-09-16T00:06:00Z", "lease-test", "mac:02:00:00:00:09:02", true)
}

func TestDomainHistoryDisabledDoesNotQueryDatabase(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED", "true")
	if err := (&DBStore{}).reconcileDomainWindow(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceSignalsMergeWithinBatch(t *testing.T) {
	e := leaseEvent("attributes-a", "02:00:00:00:09:01", "2026-09-16T00:00:00Z", "ACK")
	e.Payload["hostname"] = "office-device"
	other := leaseEvent("attributes-b", "02:00:00:00:09:01", "2026-09-16T00:01:00Z", "ACK")
	other.Payload["requested_options"] = "1,3,6,15"
	s := BuildIdentityState([]normalized.Event{e, other})
	if len(s.Endpoints) != 1 || s.Endpoints[0].Attributes["hostname"] != "office-device" || s.Endpoints[0].Attributes["requested_options"] != "1,3,6,15" {
		t.Fatalf("lost signal attributes: %+v", s.Endpoints)
	}
}
