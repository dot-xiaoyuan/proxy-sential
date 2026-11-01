package discovery

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type onlySecondStreamStateArg struct{}

func (onlySecondStreamStateArg) Match(value driver.Value) bool {
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return false
	}
	var states []streamDiscoveryState
	return json.Unmarshal(raw, &states) == nil && len(states) == 1 && states[0].Device == "device-2"
}

// A fact may be rewritten without changing the published state. The read
// model must not contend on its global version lock in that case.
func TestPublishStreamDiscoveryStatesSkipsUnchangedRow(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	fact := streamDiscoveryFact{
		Epoch: "fresh", Device: "device-1", Key: "printer", Scope: "scope-1",
		Event: "event-1", EvidenceEvent: "event-1", Protocol: "dns_sd", CandidateType: "printer", CandidateReason: "announced",
		Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour),
	}
	old, err := buildStreamDiscoveryState("fresh", fact.Device, []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	oldRaw, _ := json.Marshal(old.Document)
	repeat := fact
	repeat.Event = "event-2"
	repeat.Observed = fact.Observed.Add(2 * time.Second)
	repeat.ValidUntil = fact.ValidUntil.Add(2 * time.Second)
	factRaw, _ := json.Marshal(repeat)
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow(old.Device, old.Scope, old.LastDeviceType, old.LastCategory, old.FirstSeen, old.LastSeen, *old.ExpiresAt, oldRaw))
	mock.ExpectQuery("JOIN LATERAL").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "fact"}).AddRow(fact.Device, factRaw))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := publishStreamDiscoveryStates(context.Background(), tx, "fresh", []string{fact.Device}, map[string]int{fact.Device: 0}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishStreamDiscoveryStatesWritesOnlyChangedRow(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	base := streamDiscoveryFact{Epoch: "fresh", Scope: "scope-1", Protocol: "arp", Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
	first := base
	first.Device, first.Event = "device-1", "unchanged"
	second := base
	second.Device, second.Event = "device-2", "changed"
	oldFirst, err := buildStreamDiscoveryState("fresh", first.Device, []streamDiscoveryFact{first}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	oldSecond, err := buildStreamDiscoveryState("fresh", second.Device, []streamDiscoveryFact{second}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	oldFirstRaw, _ := json.Marshal(oldFirst.Document)
	oldSecondRaw, _ := json.Marshal(oldSecond.Document)
	second.Observed = now
	second.ValidUntil = now.Add(2 * time.Hour)
	firstRaw, _ := json.Marshal(first)
	secondRaw, _ := json.Marshal(second)
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow(oldFirst.Device, oldFirst.Scope, oldFirst.LastDeviceType, oldFirst.LastCategory, oldFirst.FirstSeen, oldFirst.LastSeen, *oldFirst.ExpiresAt, oldFirstRaw).
			AddRow(oldSecond.Device, oldSecond.Scope, oldSecond.LastDeviceType, oldSecond.LastCategory, oldSecond.FirstSeen, oldSecond.LastSeen, *oldSecond.ExpiresAt, oldSecondRaw))
	mock.ExpectQuery("JOIN LATERAL").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "fact"}).AddRow(first.Device, firstRaw).AddRow(second.Device, secondRaw))
	mock.ExpectExec("SELECT pg_advisory_xact_lock\\(9184,213\\)").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_discovery_device_state").WithArgs(onlySecondStreamStateArg{}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := publishStreamDiscoveryStates(context.Background(), tx, "fresh", []string{first.Device, second.Device}, map[string]int{first.Device: 0, second.Device: 0}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryStateStoredComparisonIsConservative(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	fact := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Event: "event-1", Observed: now, FirstObserved: now, ValidUntil: now.Add(time.Hour)}
	old, err := buildStreamDiscoveryState("fresh", fact.Device, []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(old.Document)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&old.Document); err != nil {
		t.Fatal(err)
	}
	if !streamDiscoveryStateMatchesStored(old, old) {
		t.Fatal("identical state did not match")
	}
	changed := old
	changed.LastSeen = now.Add(time.Second)
	if streamDiscoveryStateMatchesStored(old, changed) {
		t.Fatal("late observation was skipped")
	}
	changed = old
	expires := now.Add(2 * time.Hour)
	changed.ExpiresAt = &expires
	if streamDiscoveryStateMatchesStored(old, changed) {
		t.Fatal("expiry change was skipped")
	}
	changed = old
	changed.Document = map[string]any{"current": false}
	if streamDiscoveryStateMatchesStored(old, changed) {
		t.Fatal("withdrawal or correction was skipped")
	}
	changed = old
	old.Document = map[string]any{"counter": json.Number("9007199254740993")}
	changed.Document = map[string]any{"counter": float64(9007199254740992)}
	if streamDiscoveryStateMatchesStored(old, changed) {
		t.Fatal("large JSON number was rounded into a false match")
	}
}

func TestCoalesceStreamDiscoveryStateAfterDatabaseJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	fact := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Event: "first", EvidenceEvent: "first", CandidateType: "printer", Observed: now, FirstObserved: now, ValidUntil: now.Add(time.Hour)}
	old, err := buildStreamDiscoveryState("fresh", fact.Device, []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(old.Document)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&old.Document); err != nil {
		t.Fatal(err)
	}
	repeat := fact
	repeat.Event = "second"
	repeat.Observed = now.Add(2 * time.Second)
	repeat.ValidUntil = fact.ValidUntil.Add(2 * time.Second)
	next, err := buildStreamDiscoveryState("fresh", fact.Device, []streamDiscoveryFact{repeat}, &old, repeat.Observed)
	if err != nil {
		t.Fatal(err)
	}
	next = coalesceStreamDiscoveryStateFreshness(&old, next, repeat.Observed)
	if !next.LastSeen.Equal(old.LastSeen) || !next.ExpiresAt.Equal(*old.ExpiresAt) || !streamDiscoveryStateMatchesStored(old, next) {
		t.Fatalf("database JSON round trip defeated repeat coalescing: old=%+v next=%+v", old, next)
	}
}

func TestStreamDiscoveryEvidenceCountExactDatabaseNumber(t *testing.T) {
	for _, test := range []struct {
		value string
		count int
		valid bool
	}{
		{`1000000000000`, 1000000000000, true},
		{`1000000000001`, 0, false},
		{`1.5`, 0, false},
		{`-1`, 0, false},
	} {
		count, valid := streamDiscoveryEvidenceCount(map[string]any{"evidence_count": json.Number(test.value)})
		if count != test.count || valid != test.valid {
			t.Fatalf("%s: got (%d,%t) want (%d,%t)", test.value, count, valid, test.count, test.valid)
		}
	}
}

func BenchmarkStreamDiscoveryStateStoredComparison(b *testing.B) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	fact := streamDiscoveryFact{Epoch: "fresh", Device: "device-1", Scope: "scope-1", Event: "event-1", EvidenceEvent: "event-1", CandidateType: "printer", Observed: now, FirstObserved: now, ValidUntil: now.Add(time.Hour)}
	state, err := buildStreamDiscoveryState("fresh", fact.Device, []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		b.Fatal(err)
	}
	raw, err := json.Marshal(state.Document)
	if err != nil {
		b.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&state.Document); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !streamDiscoveryStateMatchesStored(state, state) {
			b.Fatal("unchanged state compared different")
		}
	}
}
