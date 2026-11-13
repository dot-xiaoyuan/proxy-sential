package discovery

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type renewedStateArgument struct{ wantUntil time.Time }

func (want renewedStateArgument) Match(value driver.Value) bool {
	var raw []byte
	switch v := value.(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	default:
		return false
	}
	var states []streamDiscoveryState
	if json.Unmarshal(raw, &states) != nil || len(states) != 1 {
		return false
	}
	return states[0].ExpiresAt != nil && states[0].ExpiresAt.Equal(want.wantUntil) && states[0].Document["current"] == true
}

func TestStreamRepeatStateSkipRejectsLateCorrectionWithdrawalAndExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	prior := streamDiscoveryFact{Device: "device-a", Scope: "scope-a", SemanticHash: "same", Event: "one", Revision: 0,
		Observed: now.Add(-2 * time.Second), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)}
	next := prior
	next.Event = "two"
	next.Observed = now
	next.ValidUntil = now.Add(time.Minute)
	decision := mergeStreamDiscoveryFact(&prior, next)
	if _, ok := streamRepeatStateCandidate(&prior, next, decision); !ok {
		t.Fatal("bounded positive repeat was not eligible")
	}
	for name, mutate := range map[string]func(*streamDiscoveryFact){
		"late":                      func(f *streamDiscoveryFact) { f.Observed = prior.Observed.Add(-time.Second) },
		"correction":                func(f *streamDiscoveryFact) { f.SemanticHash = "changed" },
		"withdrawal":                func(f *streamDiscoveryFact) { f.Withdrawn = true },
		"shorter expiry":            func(f *streamDiscoveryFact) { f.ValidUntil = prior.ValidUntil.Add(-time.Second) },
		"earlier first observation": func(f *streamDiscoveryFact) { f.FirstObserved = prior.FirstObserved.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := next
			mutate(&candidate)
			if _, ok := streamRepeatStateCandidate(&prior, candidate, mergeStreamDiscoveryFact(&prior, candidate)); ok {
				t.Fatalf("%s entered repeat state fast path", name)
			}
		})
	}
	state := streamDiscoveryState{Scope: "scope-a", FirstSeen: prior.FirstObserved, LastSeen: prior.Observed,
		ExpiresAt: &prior.ValidUntil, Document: map[string]any{"current": true, "evidence_count": 1, "last_observed_ip": ""}}
	candidate, _ := streamRepeatStateCandidate(&prior, next, decision)
	if !canSkipStreamRepeatState(state, candidate, now) {
		t.Fatal("fresh, unchanged state did not qualify")
	}
	state.Document["evidence_count"] = 2
	if !canSkipStreamRepeatState(state, candidate, now) {
		t.Fatal("safe bounded skip should also apply to multi-fact state")
	}
	state.Document["last_observed_ip"] = "10.2.3.5"
	if canSkipStreamRepeatState(state, candidate, now) {
		t.Fatal("changed observed IP must rebuild state")
	}
	state.Document["last_observed_ip"] = ""
	nearExpiry := now.Add(4 * time.Second)
	state.ExpiresAt = &nearExpiry
	if canSkipStreamRepeatState(state, candidate, now) {
		t.Fatal("expiry inside coalescing window was skipped")
	}
}

func TestStreamRepeatStateDeltaRequiresSingleUnchangedFactAndStableValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := now.Add(-time.Hour)
	oldUntil := now.Add(time.Minute)
	old := streamDiscoveryState{Scope: "scope-a", FirstSeen: first, LastSeen: now.Add(-20 * time.Second),
		ExpiresAt: &oldUntil, Document: map[string]any{"current": true, "evidence_count": 1, "last_observed_ip": "10.2.3.4", "last_seen": now.Add(-20 * time.Second).Format(time.RFC3339Nano)}}
	repeat := streamRepeatStateSkip{Scope: "scope-a", FirstObserved: first, LastObserved: now,
		ValidUntil: now.Add(2 * time.Minute), IP: "10.2.3.4"}
	delta, ok := streamRepeatStateDelta(old, repeat, now)
	if !ok || !delta.LastSeen.Equal(now) || delta.ExpiresAt == nil || !delta.ExpiresAt.Equal(repeat.ValidUntil) {
		t.Fatalf("single-fact repeat should refresh exact heartbeat and lease: %+v ok=%t", delta, ok)
	}
	for name, mutate := range map[string]func(*streamDiscoveryState, *streamRepeatStateSkip){
		"multiple facts":      func(s *streamDiscoveryState, _ *streamRepeatStateSkip) { s.Document["evidence_count"] = 2 },
		"changed observed IP": func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.IP = "10.2.3.5" },
		"malformed observed IP": func(s *streamDiscoveryState, _ *streamRepeatStateSkip) {
			s.Document["last_observed_ip"] = map[string]any{"ip": "10.2.3.4"}
		},
		"malformed last seen": func(s *streamDiscoveryState, _ *streamRepeatStateSkip) {
			s.Document["last_seen"] = map[string]any{"at": "invalid"}
		},
		"changed scope":             func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.Scope = "scope-b" },
		"earlier first observation": func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.FirstObserved = first.Add(-time.Second) },
		"late observation":          func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.LastObserved = now.Add(-21 * time.Second) },
		"future observation":        func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.LastObserved = now.Add(time.Second) },
		"submicro observation":      func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.LastObserved = now.Add(-time.Nanosecond) },
		"submicro lease": func(_ *streamDiscoveryState, r *streamRepeatStateSkip) {
			r.ValidUntil = r.ValidUntil.Add(time.Nanosecond)
		},
		"shrinking lease": func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.ValidUntil = oldUntil.Add(-time.Second) },
		"expired old state": func(s *streamDiscoveryState, _ *streamRepeatStateSkip) {
			at := now.Add(-time.Second)
			s.ExpiresAt = &at
		},
		"new lease expired": func(_ *streamDiscoveryState, r *streamRepeatStateSkip) { r.ValidUntil = now.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			state := old
			state.Document = map[string]any{"current": true, "evidence_count": 1, "last_observed_ip": "10.2.3.4", "last_seen": now.Add(-20 * time.Second).Format(time.RFC3339Nano)}
			candidate := repeat
			mutate(&state, &candidate)
			if _, ok := streamRepeatStateDelta(state, candidate, now); ok {
				t.Fatal("changed or unsafe repeat entered exact state delta")
			}
		})
	}
	expired := old
	expired.Document = map[string]any{"current": false, "evidence_count": 1, "last_observed_ip": "10.2.3.4", "last_seen": now.Add(-20 * time.Second).Format(time.RFC3339Nano)}
	expired.ExpiresAt = nil
	expired.LastSeen = now.Add(-20 * time.Second)
	repeat.LastObserved = now.Add(-2 * time.Second)
	repeat.ValidUntil = now.Add(-time.Second)
	delta, ok = streamRepeatStateDelta(expired, repeat, now)
	if !ok || delta.ExpiresAt != nil || !delta.LastSeen.Equal(repeat.LastObserved) {
		t.Fatalf("expired repeat should refresh last_seen without reviving a device: %+v ok=%t", delta, ok)
	}
	repeat.ValidUntil = now.Add(time.Second)
	if _, ok := streamRepeatStateDelta(expired, repeat, now); ok {
		t.Fatal("renewed live lease must enter the full transition path")
	}
}

func TestStreamRepeatStateDeltaAvoidsFactRescanAndPublishesExactHeartbeat(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldUntil := now.Add(time.Minute)
	newUntil := now.Add(2 * time.Minute)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldStateRaw, err := json.Marshal(map[string]any{"current": true, "evidence_count": 1,
		"last_observed_ip": "10.2.3.4", "last_seen": now.Add(-20 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state WHERE epoch=").WithArgs("epoch-a", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow("device-a", "scope-a", "", "", now.Add(-time.Hour), now.Add(-20*time.Second), oldUntil, oldStateRaw))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(9184,213\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE stream_discovery_device_state`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate := map[string]streamRepeatStateSkip{"device-a": {Scope: "scope-a", FirstObserved: now.Add(-time.Hour),
		LastObserved: now, ValidUntil: newUntil, IP: "10.2.3.4"}}
	var rows int64
	if err := publishStreamDiscoveryStatesCountWithRepeats(context.Background(), tx, "epoch-a", []string{"device-a"}, nil, candidate, &rows); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("exact heartbeat state row count=%d, want 1", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRepeatStateDeltaMismatchRollsBackForReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldUntil := now.Add(time.Minute)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldStateRaw, err := json.Marshal(map[string]any{"current": true, "evidence_count": 1,
		"last_observed_ip": "10.2.3.4", "last_seen": now.Add(-20 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state WHERE epoch=").WithArgs("epoch-a", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow("device-a", "scope-a", "", "", now.Add(-time.Hour), now.Add(-20*time.Second), oldUntil, oldStateRaw))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(9184,213\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE stream_discovery_device_state`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate := map[string]streamRepeatStateSkip{"device-a": {Scope: "scope-a", FirstObserved: now.Add(-time.Hour),
		LastObserved: now, ValidUntil: now.Add(2 * time.Minute), IP: "10.2.3.4"}}
	if err := publishStreamDiscoveryStatesCountWithRepeats(context.Background(), tx, "epoch-a", []string{"device-a"}, nil, candidate, nil); err == nil {
		t.Fatal("missing state delta did not fail segment transaction")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRepeatSkipsFactRescanWhenExpiryIsSafe(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldObserved := now.Add(-2 * time.Second)
	longExpiry := now.Add(time.Minute)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state WHERE epoch=").WithArgs("epoch-a", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow("device-a", "scope-a", "", "", now.Add(-time.Minute), oldObserved, longExpiry, []byte(`{"current":true,"evidence_count":1,"last_observed_ip":""}`)))
	mock.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate := map[string]streamRepeatStateSkip{"device-a": {Scope: "scope-a", FirstObserved: now.Add(-time.Minute), LastObserved: now, ValidUntil: now.Add(2 * time.Minute)}}
	if err := publishStreamDiscoveryStatesCountWithRepeats(context.Background(), tx, "epoch-a", []string{"device-a"}, nil, candidate, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// After a repeat extends the fact lease, the old state expiry remains an
// indexed durable wake. Even with no subsequent input, the expiry worker must
// read the renewed fact and publish its later valid_until.
func TestStreamRepeatOldExpiryRefreshesRenewedFactWithoutNewInput(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldExpiry := now.Add(-time.Second)
	newExpiry := now.Add(time.Minute)
	fact := streamDiscoveryFact{Epoch: "epoch-a", Device: "device-a", Key: "fact-a", Scope: "scope-a", Event: "repeat-two",
		Observed: now.Add(-2 * time.Second), FirstObserved: now.Add(-time.Minute), ValidUntil: newExpiry,
		Protocol: "dns_sd", SemanticHash: "same", IP: "10.2.3.4", Sensor: "sensor-a"}
	factRaw, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM stream_discovery_device_state WHERE expires_at<=now\(\)`).WithArgs(100).
		WillReturnRows(sqlmock.NewRows([]string{"epoch", "device_key"}).AddRow("epoch-a", "device-a"))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(hashtextextended`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT mac,ip,sensor_id,site,domain`).WillReturnRows(sqlmock.NewRows([]string{"mac", "ip", "sensor_id", "site", "domain", "vlan", "vrf", "interface_name", "protocol", "address_binding", "has_fields"}))
	mock.ExpectQuery(`FROM stream_discovery_device_state WHERE epoch=`).WithArgs("epoch-a", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow("device-a", "scope-a", "", "", now.Add(-time.Minute), now.Add(-4*time.Second), oldExpiry, []byte(`{"current":true,"evidence_count":1}`)))
	mock.ExpectQuery(`JOIN LATERAL`).WithArgs("epoch-a", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"device_key", "fact"}).AddRow("device-a", factRaw))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(9184,213\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_discovery_device_state`).WithArgs(renewedStateArgument{newExpiry}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	count, err := (StreamDiscoveryProjector{DB: db}).ExpireStreamDiscoveryStates(context.Background(), 100)
	if err != nil || count != 1 {
		t.Fatalf("expiry did not refresh extended lease: count=%d err=%v", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRepeatProjectionStillCommitsFactAndReceiptBeforeStateSkip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	event := streamDiscoveryEvent("repeat-two", now.Format(time.RFC3339Nano), 600)
	segment := streamlog.Segment{Epoch: "epoch-a", Source: "dns-sd", SourcePath: "/capture/dns.log",
		AcceptedAt: now, ArchiveMonth: now.Format("200601"), Events: []normalized.Event{event}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || !prepared[0].HasFact {
		t.Fatalf("prepare repeat: %v", err)
	}
	next := prepared[0].Fact
	prior := next
	prior.Event = "epoch-a:repeat-one"
	prior.EvidenceEvent = prior.Event
	prior.Observed = now.Add(-2 * time.Second)
	prior.FirstObserved = now.Add(-time.Minute)
	prior.ValidUntil = now.Add(2 * time.Minute)
	recognitionRaw, _ := json.Marshal(prior.RecognitionFields)
	oldStateRaw, _ := json.Marshal(map[string]any{"current": true, "evidence_count": 1, "last_observed_ip": next.IP})
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
		sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow(next.Device, next.Scope, "", "", prior.FirstObserved, prior.Observed, prior.ValidUntil, oldStateRaw))
	if next.IP != "" && len(next.RecognitionFields) > 0 {
		mock.ExpectQuery(`WITH scopes AS`).WillReturnRows(sqlmock.NewRows([]string{"mac", "saturated"}))
	}
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "repeat-segment", segment); err != nil {
		t.Fatalf("replayed repeat was not fully confirmed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRepeatProjectionCommitsFactAndReceiptWithExactStateDelta(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	event := streamDiscoveryEvent("repeat-delta", now.Format(time.RFC3339Nano), 600)
	segment := streamlog.Segment{Epoch: "epoch-a", Source: "dns-sd", SourcePath: "/capture/dns.log",
		AcceptedAt: now, ArchiveMonth: now.Format("200601"), Events: []normalized.Event{event}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || !prepared[0].HasFact {
		t.Fatalf("prepare repeat: %v", err)
	}
	next := prepared[0].Fact
	prior := next
	prior.Event = "epoch-a:repeat-before-delta"
	prior.EvidenceEvent = prior.Event
	prior.Observed = now.Add(-20 * time.Second)
	prior.FirstObserved = now.Add(-time.Minute)
	prior.ValidUntil = now.Add(2 * time.Minute)
	recognitionRaw, _ := json.Marshal(prior.RecognitionFields)
	oldStateRaw, _ := json.Marshal(map[string]any{"current": true, "evidence_count": 1,
		"last_observed_ip": next.IP, "last_seen": prior.Observed})
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
		sqlmock.NewRows([]string{"device_key", "scope_id", "last_device_type", "last_category", "first_seen", "last_seen", "expires_at", "document"}).
			AddRow(next.Device, next.Scope, "", "", prior.FirstObserved, prior.Observed, prior.ValidUntil, oldStateRaw))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(9184,213\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE stream_discovery_device_state`).WillReturnResult(sqlmock.NewResult(0, 1))
	if next.IP != "" && len(next.RecognitionFields) > 0 {
		mock.ExpectQuery(`WITH scopes AS`).WillReturnRows(sqlmock.NewRows([]string{"mac", "saturated"}))
	}
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "repeat-delta-segment", segment); err != nil {
		t.Fatalf("replayed repeat did not commit fact, receipt and exact state: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
