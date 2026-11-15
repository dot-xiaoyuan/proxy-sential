package discovery

import (
	"context"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestDHCPClientPostgresScopeReplayAndLeaseSeparation(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute)
	request := hardwareTestObservation(at)
	request.Origin, request.IP, request.ID, request.EventID = "dhcp_client", "", "request", "request"
	request.Evidence = normalized.Event{Subject: map[string]any{"mac": request.MAC}, Payload: map[string]any{"dhcp_log_kind": "dhcp-message", "request_only": true, "msg_types": "REQUEST", "client_chaddr": request.MAC, "vendor_class": "H3C. H3C WA5320H", "requested_options": "1,3,6"}, RawRef: map[string]any{"content_sha256": "request-reference"}}
	request.ValidUntil = at.Add(10 * time.Minute)
	if err := EnqueueHardwareObservations(ctx, db, []Observation{request, request}); err != nil {
		t.Fatal(err)
	}
	var facts, queued int
	db.QueryRow(`SELECT count(*) FROM passive_hardware_facts`).Scan(&facts)
	db.QueryRow(`SELECT count(*) FROM passive_hardware_dirty`).Scan(&queued)
	if facts != 1 || queued != 1 {
		t.Fatalf("duplicate expanded storage: %d/%d", facts, queued)
	}
	if _, err := ProcessHardwareProjection(ctx, db, "sensor", 10); err != nil {
		t.Fatal(err)
	}
	var kind, status string
	db.QueryRow(`SELECT hardware_type,hardware_type_status FROM passive_hardware_current`).Scan(&kind, &status)
	if kind != "" || status != "candidate" {
		t.Fatalf("unadapted fingerprint promoted as certain type: %s/%s", kind, status)
	}
	if err := EnqueueHardwareObservations(ctx, db, []Observation{request}); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT count(*) FROM passive_hardware_dirty`).Scan(&queued)
	if queued != 0 {
		t.Fatal("identical request requeued hardware")
	}
	ack := request
	ack.Origin, ack.IP, ack.ID, ack.EventID = "dhcp", "10.0.0.2", "ack", "ack"
	ack.Evidence = normalized.Event{Payload: map[string]any{"assigned_addr": ack.IP, "msg_types": "ACK", "vendor_class": "H3C. H3C WA5320H"}}
	if err := EnqueueHardwareObservations(ctx, db, []Observation{ack}); err != nil {
		t.Fatal(err)
	}
	if _, err := ProcessHardwareProjection(ctx, db, "sensor", 10); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT hardware_type,hardware_type_status FROM passive_hardware_current`).Scan(&kind, &status)
	if kind != "access_point" || status != "identified" {
		t.Fatalf("ACK model lost after client fields: %s/%s", kind, status)
	}
	other := request
	other.VLAN = "21"
	tx, _ := db.BeginTx(ctx, nil)
	if err := EnqueueHardwareObservations(ctx, tx, []Observation{other}); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	db.QueryRow(`SELECT count(DISTINCT identity_key) FROM passive_hardware_facts`).Scan(&facts)
	if facts != 1 {
		t.Fatal("rollback leaked another identity")
	}
	if err := EnqueueHardwareObservations(ctx, db, []Observation{other}); err != nil {
		t.Fatal(err)
	}
	if _, err := ProcessHardwareProjection(ctx, db, "sensor", 10); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT hardware_type_status FROM passive_hardware_current WHERE vlan='21'`).Scan(&status)
	if status != "candidate" {
		t.Fatal("cross-VLAN inherited ACK model")
	}
	released := ack
	released.Withdrawn = true
	released.ObservedAt = at.Add(20 * time.Second)
	released.ValidUntil = released.ObservedAt
	released.ID, released.EventID = "release", "release"
	if err := EnqueueHardwareObservations(ctx, db, []Observation{released, ack}); err != nil {
		t.Fatal(err)
	}
	if _, err := ProcessHardwareProjection(ctx, db, "sensor", 10); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT hardware_type_status FROM passive_hardware_current WHERE vlan='20'`).Scan(&status)
	if status != "revoked" {
		t.Fatalf("client clue or late ACK revived revoked type: %s", status)
	}
}
