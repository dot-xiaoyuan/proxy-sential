package store

import (
	"context"
	"os"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestDeviceNamesPostgresReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
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
	now := time.Now().UTC().Truncate(time.Second)
	id := "mac:aa:bb:cc:dd:ee:a1"
	dhcp := leaseEvent("name-lease-a", "aa:bb:cc:dd:ee:a1", now.Format(time.RFC3339Nano), "ACK")
	dhcp.Payload["hostname"] = "workstation-a"
	dhcp.Payload["client_fqdn"] = "workstation-a.example"
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{dhcp}); err != nil {
		t.Fatal(err)
	}
	e := normalized.Event{EventID: "name-response-a", Type: "device", Timestamp: now.Add(time.Second).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "lease-test"}, Subject: map[string]any{"ip": "192.0.2.200"}, Payload: map[string]any{"origin": "mdns", "is_response": true, "record_type": "A", "record_name": "workstation-a.local", "record_address": "192.0.2.192", "record_ttl": 120}}
	if err = s.processDeviceNamesReceived(ctx, []normalized.Event{dhcp, e, e}, time.Now().Add(-100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// Invalid new events must not write evidence, including unresolved records.
	bad := e
	bad.EventID = "opaque-new"
	bad.Payload = map[string]any{"origin": "mdns", "is_response": true, "record_type": "A", "record_name": "4853000c-1c0f-4133-8c69-69da2675d0d0.local", "record_address": "192.0.2.192", "record_ttl": 120}
	if err = s.ProcessDeviceNames(ctx, []normalized.Event{bad, bad}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM device_name_evidence WHERE event_id='opaque-new'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("opaque event persisted %d %v", count, err)
	}
	// Replay cleanup against old data, and verify it is idempotent and preserves useful records.
	for _, value := range []string{"4853000c-1c0f-4133-8c69-69da2675d0d0.local", "0123456789abcdef.local", "aa-bb-cc-dd-ee-ff.local", "123.local", "bad/name.local", "_http._tcp.local"} {
		if _, err = s.db.ExecContext(ctx, `INSERT INTO device_name_evidence(sensor_id,event_id,source,value,endpoint_id,observed_at,evidence) VALUES('legacy','opaque-old','mdns_hostname',$1,$2,now(),'{}')`, value, id); err != nil {
			t.Fatal(err)
		}
	}
	cleanup, err := os.ReadFile("../../migrations/postgres/055_device_name_quality.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = s.db.ExecContext(ctx, string(cleanup)); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM device_name_evidence WHERE event_id='opaque-old'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("old opaque names retained %d %v", count, err)
	}
	page, err := s.ListDeviceNameEvidence(ctx, id, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Items[0].ProcessingLatencyMillis == nil || *page.Items[0].ProcessingLatencyMillis < 100 {
		t.Fatal("missing queue latency")
	}
	if page.Total != 3 {
		t.Fatalf("duplicate count %d", page.Total)
	}
	names, err := s.DeviceNames(ctx, []string{id}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if names[id] == nil || names[id].Value != "workstation-a.example" {
		t.Fatal(names)
	}
	if err = s.UpdateDeviceNameNote(ctx, id, "设备备注", "tester"); err != nil {
		t.Fatal(err)
	}
	names, err = s.DeviceNames(ctx, []string{id}, now.Add(2*time.Second))
	if err != nil || !names[id].Manual {
		t.Fatalf("manual: %+v %v", names, err)
	}
	if err = s.UpdateDeviceNameNote(ctx, id, "", "tester"); err != nil {
		t.Fatal(err)
	}
	names, err = s.DeviceNames(ctx, []string{id}, now.Add(2*time.Second))
	if err != nil || names[id].Manual {
		t.Fatal("clear manual", err)
	}
	// The response's source is not the advertised endpoint. Attribution must use the answer address.
	if page.Items[0].Source != "mdns_hostname" || page.Items[0].Attribution != "event_time_lease" {
		t.Fatal(page.Items)
	}
	b := leaseEvent("name-lease-b", "aa:bb:cc:dd:ee:a2", now.Add(3*time.Second).Format(time.RFC3339Nano), "ACK")
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{b}); err != nil {
		t.Fatal(err)
	}
	e.EventID = "name-response-b"
	e.Timestamp = now.Add(4 * time.Second).Format(time.RFC3339Nano)
	e.Payload["record_name"] = "new-device.local"
	if err = s.ProcessDeviceNames(ctx, []normalized.Event{e}); err != nil {
		t.Fatal(err)
	}
	names, err = s.DeviceNames(ctx, []string{id, "mac:aa:bb:cc:dd:ee:a2"}, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if names[id].Value != "workstation-a.example" || names["mac:aa:bb:cc:dd:ee:a2"].Value != "new-device" {
		t.Fatal("IP reassignment", names)
	}
	e.EventID = "other-sensor"
	e.Observer["sensor_id"] = "other"
	if err = s.ProcessDeviceNames(ctx, []normalized.Event{e}); err != nil {
		t.Fatal(err)
	}
	var unresolved int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM device_name_evidence WHERE event_id='other-sensor' AND endpoint_id=''`).Scan(&unresolved); err != nil || unresolved != 1 {
		t.Fatal("sensor isolation", err)
	}
	// A service alias must remain separate from the hostname and follow the SRV target.
	srv := e
	srv.EventID = "service-alias"
	srv.Observer = map[string]any{"sensor_id": "lease-test"}
	srv.Payload = map[string]any{"origin": "mdns", "is_response": true, "record_type": "SRV", "record_name": "Office._ipp._tcp.local", "service_target": "new-device.local", "record_ttl": 120}
	if err = s.ProcessDeviceNames(ctx, []normalized.Event{srv}); err != nil {
		t.Fatal(err)
	}
	aliases, err := s.ListDeviceNameEvidence(ctx, "mac:aa:bb:cc:dd:ee:a2", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	serviceFound := false
	for _, n := range aliases.Items {
		if n.Kind == "service" {
			serviceFound = true
		}
	}
	if !serviceFound {
		t.Fatal("service target not attributed")
	}
	names, err = s.DeviceNames(ctx, []string{"mac:aa:bb:cc:dd:ee:a2"}, now.Add(5*time.Second))
	if err != nil || names["mac:aa:bb:cc:dd:ee:a2"].Value != "new-device" {
		t.Fatal("service replaced hostname", err)
	}
	// A late, simultaneous conflicting lease invalidates an earlier attribution on retry.
	conflict := leaseEvent("name-lease-conflict", "aa:bb:cc:dd:ee:a3", now.Add(3*time.Second).Format(time.RFC3339Nano), "ACK")
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{conflict}); err != nil {
		t.Fatal(err)
	}
	if err = s.RetryDeviceNames(ctx, []normalized.Event{conflict}); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err = s.db.QueryRowContext(ctx, `SELECT endpoint_id FROM device_name_evidence WHERE event_id='name-response-b'`).Scan(&owner); err != nil || owner != "" {
		t.Fatal("late conflict kept attribution", owner, err)
	}

	// Readable DHCP descriptions with a MAC suffix survive the corrective migration.
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_entities SET attributes=jsonb_set(attributes,'{hostname}','"Office Printer-20:3a:eb:e9:de:10"') WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	restore, err := os.ReadFile("../../migrations/postgres/056_device_name_readable_attributes.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, string(restore)); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM device_name_evidence WHERE endpoint_id=$1 AND value='Office Printer-20:3a:eb:e9:de:10' AND evidence->>'attribution'='legacy_attribute'`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("readable description missing %d %v", count, err)
	}

	// A complete IP must not match an IP-like manual note or a longer address.
	if err = s.UpdateDeviceNameNote(ctx, id, "192.0.2.19", "tester"); err != nil {
		t.Fatal(err)
	}
	exact, err := s.ListEndpointDevices(ctx, Query{Q: "192.0.2.19", Limit: 20})
	if err != nil || len(exact.Items) != 0 {
		t.Fatalf("IP substring/name matched: %+v %v", exact, err)
	}
	exact, err = s.ListEndpointDevices(ctx, Query{Q: "192.0.2.192", Limit: 20})
	if err != nil || len(exact.Items) == 0 {
		t.Fatalf("exact historical IP missed: %+v %v", exact, err)
	}
	defaults, err := os.ReadFile("../../migrations/postgres/057_device_name_default_labels.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"localhost", "ADY-AL00", "ICL-AL10", "HONOR-100"} {
		if _, err = s.db.ExecContext(ctx, `INSERT INTO device_name_evidence(sensor_id,event_id,source,value,endpoint_id,observed_at,evidence) VALUES('legacy','default-old','dhcp_hostname',$1,$2,now(),'{}')`, value, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.db.ExecContext(ctx, string(defaults)); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM device_name_evidence WHERE event_id='default-old'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("defaults retained %d %v", count, err)
	}

}
