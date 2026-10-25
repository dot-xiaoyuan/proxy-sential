package discovery

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type streamStateArrayConverter struct{}

func (streamStateArrayConverter) ConvertValue(v any) (driver.Value, error) { return v, nil }

func TestBuildStreamDiscoveryStateUsesNarrowFacts(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 1, 0, 0, time.UTC)
	base := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Key: "printer", Scope: "scope-1", Event: "one", Protocol: "dns_sd", CandidateType: "printer", CandidateReason: "typed printer", IP: "10.2.3.4", Name: "Printer", Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)}
	state, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{base}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if state.ClassificationStatus != "identified" || state.DeviceType != "printer" || state.LastDeviceType != "printer" || state.Document["evidence_count"] != 1 {
		t.Fatalf("typed fact was not published: %+v", state)
	}
	if state.Document["primary_ip"] != "" || state.Document["last_observed_ip"] != "10.2.3.4" || state.Document["mac"] != "" {
		t.Fatalf("unbound observation was published as current address: %+v", state.Document)
	}
	bound := base
	bound.AddressBinding = true
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{bound}, nil, now)
	if err != nil || state.Document["primary_ip"] != "10.2.3.4" {
		t.Fatalf("verified binding was not published as current address: %+v %v", state.Document, err)
	}
	repeat := base
	repeat.Event = "two"
	repeat.Observed = now
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{repeat}, &state, now)
	if err != nil || state.Document["evidence_count"] != 1 {
		t.Fatalf("repeat expanded state: %+v %v", state, err)
	}
}

func TestBuildStreamDiscoveryStateHandlesExpiryWithdrawalAndConflict(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 1, 0, 0, time.UTC)
	base := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Key: "printer", Scope: "scope-1", Event: "one", CandidateType: "printer", Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)}
	prior, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{base}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	expired := base
	expired.ValidUntil = now.Add(-time.Second)
	state, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{expired}, &prior, now)
	if err != nil || state.ClassificationStatus != "expired" || state.LastDeviceType != "printer" {
		t.Fatalf("natural expiry erased conclusion: %+v %v", state, err)
	}
	withdrawn := base
	withdrawn.Withdrawn = true
	withdrawn.Event = "withdraw"
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{withdrawn}, &prior, now)
	if err != nil || state.ClassificationStatus != "candidate" || state.LastDeviceType != "" {
		t.Fatalf("explicit withdrawal kept conclusion: %+v %v", state, err)
	}
	other := base
	other.Key = "camera"
	other.Event = "camera-event"
	other.CandidateType = "camera"
	state, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{base, other}, &prior, now)
	if err != nil || state.ClassificationStatus != "conflict" {
		t.Fatalf("conflicting types accepted: %+v %v", state, err)
	}
}

func TestBuildStreamDiscoveryStateRejectsUnboundedDevice(t *testing.T) {
	now := time.Now().UTC()
	facts := make([]streamDiscoveryFact, 257)
	for i := range facts {
		facts[i] = streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Key: "fact", Observed: now, FirstObserved: now}
	}
	if _, err := buildStreamDiscoveryState("fresh", "device-1", facts, nil, now); err == nil {
		t.Fatal("oversized device must enter repair path")
	}
}

func TestBuildStreamDiscoveryStateHighFanoutKeepsExactCountAndConservativeSummary(t *testing.T) {
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	base := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Event: "old", Protocol: "ssdp", CandidateType: "printer", Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Hour), ValidUntil: now.Add(time.Minute)}
	previous, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{base}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	facts := make([]streamDiscoveryFact, maxStreamFactsPerDevice)
	for i := range facts {
		facts[i] = base
		facts[i].Observed = now.Add(-time.Duration(i) * time.Millisecond)
		facts[i].FirstObserved = facts[i].Observed
		facts[i].Event = "new"
	}
	activeUntil := now.Add(15 * time.Second) // An older fact outside the sample expires first.
	state, err := buildStreamDiscoveryStateSummary("fresh", "device-1", facts, &previous, now, 261, true, &activeUntil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.ClassificationStatus != "candidate" || state.DeviceType != "" || state.LastDeviceType != "" {
		t.Fatalf("incomplete fact set classified as certain: %+v", state)
	}
	if state.Document["facts_truncated"] != true || state.Document["evidence_count"] != 261 || state.Document["current"] != true {
		t.Fatalf("high fanout summary lost count or current state: %+v", state.Document)
	}
	if state.ExpiresAt == nil || !state.ExpiresAt.Equal(activeUntil) || !state.FirstSeen.Equal(previous.FirstSeen) {
		t.Fatalf("high fanout summary lost expiry or first sighting: %+v", state)
	}
}

func TestBuildStreamDiscoveryStateHighFanoutUsesIndexedFutureBoundary(t *testing.T) {
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	fact := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Event: "old", Observed: now.Add(-time.Hour), FirstObserved: now.Add(-time.Hour), ValidUntil: now.Add(-time.Minute)}
	previous, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	facts := make([]streamDiscoveryFact, maxStreamFactsPerDevice)
	for i := range facts {
		facts[i] = fact
	}
	nextFuture := now.Add(time.Second)
	state, err := buildStreamDiscoveryStateSummary("fresh", "device-1", facts, &previous, now, 257, true, nil, &nextFuture)
	if err != nil || state.Document["current"] != false || state.ExpiresAt == nil || !state.ExpiresAt.Equal(nextFuture) {
		t.Fatalf("hidden future boundary was lost: %+v %v", state, err)
	}
}

func TestPublishStreamDiscoveryStatesHighFanoutUsesBoundedRowsAndPriorCount(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	old := streamDiscoveryState{Device: "device-1", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Minute), Document: map[string]any{"evidence_count": 214}}
	oldRaw, _ := json.Marshal(old.Document)
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow(old.Device, "", "", old.FirstSeen, old.LastSeen, nil, oldRaw))
	factRows := sqlmock.NewRows([]string{"device_key", "fact"})
	for i := 0; i < maxStreamFactsPerDevice+1; i++ {
		fact := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Event: "event", Protocol: "ssdp", Observed: now.Add(-time.Duration(i) * time.Millisecond), FirstObserved: now.Add(-time.Duration(i) * time.Millisecond), ValidUntil: now.Add(time.Minute)}
		raw, _ := json.Marshal(fact)
		factRows.AddRow("device-1", raw)
	}
	mock.ExpectQuery("JOIN LATERAL").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(factRows)
	mock.ExpectQuery("SELECT v.device_key,").WithArgs("fresh", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "active", "future"}).AddRow("device-1", now.Add(10*time.Second), nil))
	mock.ExpectExec("INSERT INTO stream_discovery_device_state").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := publishStreamDiscoveryStates(context.Background(), tx, "fresh", []string{"device-1"}, map[string]int{"device-1": 47}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCoalesceStreamDiscoveryStateRepeatWithinFreshnessWindow(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	fact := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Key: "printer", Scope: "scope-1", Event: "one", EvidenceEvent: "one", CandidateType: "printer", Observed: now, FirstObserved: now, ValidUntil: now.Add(time.Minute)}
	old, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	repeat := fact
	repeat.Event = "two"
	repeat.Observed = now.Add(2 * time.Second)
	repeat.ValidUntil = now.Add(time.Minute + 2*time.Second)
	next, err := buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{repeat}, &old, repeat.Observed)
	if err != nil {
		t.Fatal(err)
	}
	coalesced := coalesceStreamDiscoveryStateFreshness(&old, next, repeat.Observed)
	if !coalesced.LastSeen.Equal(old.LastSeen) || !coalesced.ExpiresAt.Equal(*old.ExpiresAt) {
		t.Fatalf("small repeat rewrote state: %+v", coalesced)
	}
	repeat.Observed = now.Add(6 * time.Second)
	repeat.ValidUntil = now.Add(time.Minute + 6*time.Second)
	next, err = buildStreamDiscoveryState("fresh", "device-1", []streamDiscoveryFact{repeat}, &old, repeat.Observed)
	if err != nil {
		t.Fatal(err)
	}
	coalesced = coalesceStreamDiscoveryStateFreshness(&old, next, repeat.Observed)
	if !coalesced.LastSeen.Equal(repeat.Observed) {
		t.Fatalf("necessary freshness was suppressed: %+v", coalesced)
	}
}
