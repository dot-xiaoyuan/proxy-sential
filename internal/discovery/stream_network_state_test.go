package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStreamNetworkTypeIsSeparateFromIoTClassification(t *testing.T) {
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	router := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Key: "router", Scope: "scope-1", Event: "event-router", EvidenceEvent: "event-router", Protocol: "ssdp", DeviceType: "gateway", Excluded: true, Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(2 * time.Minute)}
	state, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{router}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastDeviceType != "" || state.DeviceType != "" || state.ClassificationStatus != "candidate" {
		t.Fatalf("network clue entered IoT classification: %+v", state)
	}
	if state.NetworkDeviceType != "gateway" || state.NetworkTypeStatus != "clue" || state.NetworkTypeLastSeen != router.Observed || state.Document["network_type_status"] != "clue" {
		t.Fatalf("current network clue missing: %+v", state)
	}
	if got := state.Document["network_type_evidence_ids"].([]string); len(got) != 1 || got[0] != router.Event {
		t.Fatalf("network evidence reference missing: %+v", state.Document)
	}
	legacyGateway := router
	legacyGateway.Excluded = false // Stored before gateway joined the IoT exclusion set.
	legacy, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{legacyGateway}, nil, now)
	if err != nil || legacy.NetworkDeviceType != "gateway" {
		t.Fatalf("old gateway fact was lost by new network projection: %+v %v", legacy, err)
	}
	if !excludedStreamDeviceType("gateway") {
		t.Fatal("gateway must not enter IoT classification")
	}

	// A still-active ARP heartbeat cannot keep an expired network type current.
	arp := router
	arp.Key, arp.Event, arp.Protocol, arp.DeviceType, arp.Excluded = "arp", "event-arp", "arp", "", false
	arp.Observed, arp.ValidUntil = now, now.Add(time.Hour)
	expired := router
	expired.ValidUntil = now.Add(-time.Second)
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{arp, expired}, &state, now)
	if err != nil || state.Document["current"] != true || state.NetworkDeviceType != "" || state.LastNetworkDeviceType != "gateway" || state.NetworkTypeStatus != "expired" {
		t.Fatalf("expired network clue remained current: %+v %v", state, err)
	}
	if got := state.Document["network_type_evidence_ids"].([]string); len(got) != 1 || got[0] != router.Event || state.NetworkTypeFirstSeen != router.FirstObserved {
		t.Fatalf("historical clue lost its evidence and first observation: %+v", state.Document)
	}

	withdrawn := router
	withdrawn.Withdrawn, withdrawn.Event = true, "withdraw-router"
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{arp, withdrawn}, &state, now)
	if err != nil || state.NetworkTypeStatus != "" || state.LastNetworkDeviceType != "" {
		t.Fatalf("withdrawn network clue remained listed: %+v %v", state, err)
	}
}

func TestStreamNetworkTypeLateFactAndRepeatRenewal(t *testing.T) {
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	base := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Protocol: "ssdp", DeviceType: "gateway", Excluded: true, Event: "new", EvidenceEvent: "new", Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)}
	late := base
	late.Key, late.Event, late.EvidenceEvent = "older", "older", "older"
	late.Observed, late.FirstObserved, late.ValidUntil = now.Add(-time.Hour), now.Add(-time.Hour), now.Add(-30*time.Minute)
	state, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{base, late}, nil, now)
	if err != nil || state.NetworkTypeStatus != "clue" || state.NetworkTypeLastSeen != base.Observed || state.NetworkTypeValidUntil != base.ValidUntil {
		t.Fatalf("late expired fact displaced current clue: %+v %v", state, err)
	}
	decision := streamFactDecision{Result: "repeat_observation", WriteFact: true}
	if _, skip := streamRepeatStateCandidate(&base, base, decision); skip {
		t.Fatal("typed repeat skipped network lookup lease renewal")
	}
}

func TestStreamNetworkLookupWritesOnlyOnTypeChangeAndDeletesWithdrawal(t *testing.T) {
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	fact := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Protocol: "ssdp", DeviceType: "gateway", Excluded: true, Event: "event-1", Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)}
	current, err := buildStreamDiscoveryState("fresh", fact.Device, []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	withdrawn := fact
	withdrawn.Withdrawn = true
	removed, err := buildStreamDiscoveryState("fresh", fact.Device, []streamDiscoveryFact{withdrawn}, &current, now)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_discovery_network_state").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM stream_discovery_network_state").WithArgs("fresh", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := publishStreamDiscoveryNetworkStates(context.Background(), tx, []streamDiscoveryState{current}, nil); err != nil {
		t.Fatal(err)
	}
	// A state rewrite caused only by unrelated fields does not rewrite the
	// sparse lookup or add another index maintenance operation.
	if err := publishStreamDiscoveryNetworkStates(context.Background(), tx, []streamDiscoveryState{current}, map[string]streamDiscoveryState{current.Device: current}); err != nil {
		t.Fatal(err)
	}
	if err := publishStreamDiscoveryNetworkStates(context.Background(), tx, []streamDiscoveryState{removed}, map[string]streamDiscoveryState{current.Device: current}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkTypeConflictDoesNotConfirmAsset(t *testing.T) {
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	base := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Protocol: "lldp", Excluded: true, Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
	router := base
	router.Key, router.Event, router.DeviceType = "r", "router", "router"
	gateway := base
	gateway.Key, gateway.Event, gateway.DeviceType = "g", "gateway", "gateway"
	state, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{router, gateway}, nil, now)
	if err != nil || state.NetworkTypeStatus != "clue" || state.NetworkDeviceType == "" {
		t.Fatalf("router and gateway should stay in one clue family: %+v %v", state, err)
	}
	ap := base
	ap.Key, ap.Event, ap.DeviceType = "ap", "access-point", "access_point"
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{router, ap}, nil, now)
	if err != nil || state.NetworkTypeStatus != "conflict" || state.NetworkDeviceType != "" {
		t.Fatalf("conflicting network clues became an asset: %+v %v", state, err)
	}
	if state.Document["network_type_status"] != "conflict" || state.Document["network_type_reason"] == "" {
		t.Fatalf("network conflict not retained in generic state detail: %+v", state.Document)
	}
	if ids, ok := state.Document["network_type_evidence_ids"].([]string); !ok || len(ids) != 2 {
		t.Fatalf("network conflict lost fact references: %+v", state.Document)
	}

	active := router
	active.Protocol = "active"
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{active}, nil, now)
	if err != nil || state.NetworkTypeStatus != "" {
		t.Fatalf("active probe entered passive network assets: %+v %v", state, err)
	}
}
