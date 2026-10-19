package store

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
)

var reconcileScope = IdentityScope{Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth"}

var reconcileObserved = time.Date(2026, 10, 16, 7, 10, 0, 0, time.UTC)

// snapshotMember is a complete-snapshot member as CommitIdentitySnapshot receives it.
func snapshotMember(id, account, ip string) policy.Session {
	return policy.Session{
		ID: id, AccountID: account, IP: ip, Source: reconcileScope.Source, SensorID: reconcileScope.SensorID,
		CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain,
		Status: "reconcile", StartedAt: time.Date(2026, 9, 30, 17, 20, 55, 0, time.UTC),
		ConfirmedAt: reconcileObserved, HeartbeatSeconds: 1800, ReconcileSeconds: 1800,
	}
}

// eventRow is a session written from the realtime identity event path, still open.
func eventRow(id, account, ip string, confirmedAt time.Time) policy.Session {
	return policy.Session{
		ID: id, AccountID: account, IP: ip, Source: reconcileScope.Source, SensorID: reconcileScope.SensorID,
		CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain,
		Status: "start", StartedAt: confirmedAt.Add(-time.Minute), ConfirmedAt: confirmedAt,
	}
}

func snapshotWith(members ...policy.Session) IdentitySnapshot {
	return IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: "snapshot-replay", ObservedAt: reconcileObserved, IntervalSeconds: 1800, Sessions: members}
}

// applyReconcileActions replays the planned changes onto the stored rows, as the writer will.
func applyReconcileActions(rows []policy.Session, actions []sessionReconcileAction) []policy.Session {
	out := append([]policy.Session(nil), rows...)
	for _, action := range actions {
		for i := range out {
			if out[i].ID != action.SessionID {
				continue
			}
			switch action.Kind {
			case sessionReconcileConfirm:
				out[i].ConfirmedAt = action.At
			case sessionReconcileEnd:
				out[i].EndedAt, out[i].ConfirmedAt, out[i].Status = action.At, action.At, "stop"
			}
		}
		if action.Kind == sessionReconcileInsert {
			out = append(out, action.Row)
		}
	}
	return out
}

// findAction returns the single action of kind for id, ignoring unrelated actions in the same plan.
func findAction(t *testing.T, actions []sessionReconcileAction, kind sessionReconcileKind, id string) sessionReconcileAction {
	t.Helper()
	var found []sessionReconcileAction
	for _, action := range actions {
		if action.Kind == kind && action.SessionID == id {
			found = append(found, action)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want one %s for %s, got %d in %+v", kind, id, len(found), actions)
	}
	return found[0]
}

func requireOneAction(t *testing.T, actions []sessionReconcileAction, kind sessionReconcileKind, id string) sessionReconcileAction {
	t.Helper()
	if len(actions) != 1 {
		t.Fatalf("actions=%d want 1: %+v", len(actions), actions)
	}
	if actions[0].Kind != kind || actions[0].SessionID != id {
		t.Fatalf("action=%+v want kind=%s id=%s", actions[0], kind, id)
	}
	return actions[0]
}

// A snapshot member with no session row is the case the 10.157.2.191 gap exposed.
func TestSnapshotMemberWithoutSessionRowInsertsReconcileRow(t *testing.T) {
	member := snapshotMember("sess-A", "acct-1", "10.157.2.191")
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(member), nil, time.Time{})
	action := requireOneAction(t, actions, sessionReconcileInsert, "sess-A")
	if conflicts != 0 {
		t.Fatalf("conflicts=%d", conflicts)
	}
	row := action.Row
	if row.Source != reconcileScope.Source || row.Status != "reconcile" || row.IP != "10.157.2.191" || row.AccountID != "acct-1" {
		t.Fatalf("inserted row identity wrong: %+v", row)
	}
	if !row.StartedAt.Equal(member.StartedAt) {
		t.Fatalf("started_at=%s want login generation %s", row.StartedAt, member.StartedAt)
	}
	if !row.EndedAt.IsZero() || !row.ConfirmedAt.Equal(reconcileObserved) {
		t.Fatalf("open row must be confirmed at snapshot time: ended=%s confirmed=%s", row.EndedAt, row.ConfirmedAt)
	}
}

// An event-owned row for the same login only gets its confirmation time moved forward.
// Its source, status and start time are never rewritten by the snapshot.
func TestSnapshotMemberMatchingEventRowOnlyConfirms(t *testing.T) {
	rows := []policy.Session{eventRow("sess-A", "acct-1", "10.157.2.191", reconcileObserved.Add(-time.Minute))}
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(snapshotMember("sess-A", "acct-1", "10.157.2.191")), rows, time.Time{})
	action := requireOneAction(t, actions, sessionReconcileConfirm, "sess-A")
	if !action.At.Equal(reconcileObserved) || conflicts != 0 {
		t.Fatalf("confirm at=%s conflicts=%d", action.At, conflicts)
	}
}

// Replaying the same snapshot must change nothing: confirmation is idempotent.
func TestSnapshotReplayIsIdempotent(t *testing.T) {
	snapshot := snapshotWith(snapshotMember("sess-A", "acct-1", "10.157.2.191"))
	first, _ := planSnapshotSessionReconcile(snapshot, nil, time.Time{})
	rows := applyReconcileActions(nil, first)
	if len(rows) != 1 {
		t.Fatalf("rows after first apply=%d", len(rows))
	}
	second, conflicts := planSnapshotSessionReconcile(snapshot, rows, time.Time{})
	if len(second) != 0 || conflicts != 0 {
		t.Fatalf("replay produced actions=%+v conflicts=%d", second, conflicts)
	}
	third, _ := planSnapshotSessionReconcile(snapshot, rows, reconcileObserved)
	if len(third) != 0 {
		t.Fatalf("replay after lastApplied produced actions=%+v", third)
	}
}

// A reconcile-owned row that drops out of a complete snapshot ends at the snapshot time.
func TestMissingSnapshotRowEndsAtSnapshotTime(t *testing.T) {
	rows := []policy.Session{snapshotMember("sess-B", "acct-2", "10.157.2.20")}
	rows[0].ConfirmedAt = reconcileObserved.Add(-30 * time.Minute)
	actions, _ := planSnapshotSessionReconcile(snapshotWith(snapshotMember("sess-other", "acct-other", "10.0.0.250")), rows, time.Time{})
	action := findAction(t, actions, sessionReconcileEnd, "sess-B")
	if !action.At.Equal(reconcileObserved) {
		t.Fatalf("end at=%s want %s", action.At, reconcileObserved)
	}
}

// An event confirmed after the snapshot was taken is newer evidence; the snapshot must not end it.
func TestEventConfirmedAfterSnapshotIsNotEnded(t *testing.T) {
	rows := []policy.Session{eventRow("sess-C", "acct-3", "10.157.2.30", reconcileObserved.Add(time.Minute))}
	actions, _ := planSnapshotSessionReconcile(snapshotWith(), rows, time.Time{})
	if len(actions) != 0 {
		t.Fatalf("newer event row ended by older snapshot: %+v", actions)
	}
}

// A snapshot that is not newer than the last applied one must be ignored entirely.
func TestOlderSnapshotIsIgnored(t *testing.T) {
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(snapshotMember("sess-A", "acct-1", "10.157.2.191")), nil, reconcileObserved.Add(time.Hour))
	if len(actions) != 0 || conflicts != 0 {
		t.Fatalf("older snapshot applied: actions=%+v conflicts=%d", actions, conflicts)
	}
}

// Same login generation after an event-recorded logout means the logout is the stored truth.
// The snapshot must not reopen it, and the disagreement is counted for review.
func TestEndedRowIsNotReopenedBySnapshot(t *testing.T) {
	ended := eventRow("sess-D", "acct-4", "10.157.2.40", reconcileObserved.Add(-time.Hour))
	ended.EndedAt = reconcileObserved.Add(-5 * time.Minute)
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(snapshotMember("sess-D", "acct-4", "10.157.2.40")), []policy.Session{ended}, time.Time{})
	if len(actions) != 0 {
		t.Fatalf("ended session reopened: %+v", actions)
	}
	if conflicts != 1 {
		t.Fatalf("conflicts=%d want 1", conflicts)
	}
}

// Rows from another scope (other sensor or campus) are not authority for this snapshot.
func TestRowsOutsideSnapshotScopeAreUntouched(t *testing.T) {
	other := eventRow("sess-E", "acct-5", "10.1.1.5", reconcileObserved.Add(-time.Hour))
	other.SensorID = "ncu-other-sensor"
	actions, _ := planSnapshotSessionReconcile(snapshotWith(), []policy.Session{other}, time.Time{})
	if len(actions) != 0 {
		t.Fatalf("out-of-scope row changed: %+v", actions)
	}
}

// The event path and the snapshot path must derive the same session ID for the same login,
// otherwise a snapshot member can never find its event row and would duplicate it.
func TestEventAndSnapshotDeriveSameSessionID(t *testing.T) {
	raw := `{"action":1,"session_id":"S-1","user_name":"acct-1","ip":"10.157.2.191","user_mac":"90:fb:5d:a7:40:4b","add_time":1790820000}`
	record, err := legacy4k.DecodeRecordForInstance(raw, "instance-A", reconcileObserved)
	if err != nil {
		t.Fatal(err)
	}
	snapshotID := legacy4k.OnlineSessionID("instance-A", "S-1", "1790820000")
	if record["session_id"] != snapshotID {
		t.Fatalf("event session=%q snapshot session=%q", record["session_id"], snapshotID)
	}
}

const rotatedLoginKey = "S-1|1790820000"

// keyedMember is a snapshot member whose login generation is known.
func keyedMember(id, key string) policy.Session {
	member := snapshotMember(id, "acct-1", "10.157.2.191")
	member.LoginKey = key
	return member
}

// keyedRow is an open row written earlier under a (possibly previous) instance ID.
func keyedRow(id, key string, confirmedAt time.Time) policy.Session {
	row := eventRow(id, "acct-1", "10.157.2.191", confirmedAt)
	row.LoginKey = key
	return row
}

// Redis restart changes the run_id, so the same login arrives with a new session ID.
// The snapshot must confirm the existing row, not insert a duplicate and end the old one.
func TestInstanceRotationConfirmsExistingLoginInsteadOfDuplicating(t *testing.T) {
	rows := []policy.Session{keyedRow("instance-A:S-1", rotatedLoginKey, reconcileObserved.Add(-30*time.Minute))}
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(keyedMember("instance-B:S-1", rotatedLoginKey)), rows, time.Time{})
	action := requireOneAction(t, actions, sessionReconcileConfirm, "instance-A:S-1")
	if !action.At.Equal(reconcileObserved) || conflicts != 0 {
		t.Fatalf("confirm at=%s conflicts=%d", action.At, conflicts)
	}
}

// A logout recorded under the old instance is the stored truth; rotation must not revive it.
func TestInstanceRotationDoesNotReviveEndedLogin(t *testing.T) {
	ended := keyedRow("instance-A:S-1", rotatedLoginKey, reconcileObserved.Add(-time.Hour))
	ended.EndedAt = reconcileObserved.Add(-10 * time.Minute)
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(keyedMember("instance-B:S-1", rotatedLoginKey)), []policy.Session{ended}, time.Time{})
	if len(actions) != 0 || conflicts != 1 {
		t.Fatalf("actions=%+v conflicts=%d want none and 1", actions, conflicts)
	}
}

// Same source session with a different login generation is a new login, not a rotation.
func TestNewLoginGenerationIsNotAliasedToOldRow(t *testing.T) {
	rows := []policy.Session{keyedRow("instance-A:S-1", rotatedLoginKey, reconcileObserved.Add(-30*time.Minute))}
	actions, _ := planSnapshotSessionReconcile(snapshotWith(keyedMember("instance-B:S-1-new", "S-1|1790830000")), rows, time.Time{})
	if len(actions) != 2 {
		t.Fatalf("actions=%+v want insert of the new login and end of the old one", actions)
	}
	var inserted, ended bool
	for _, action := range actions {
		inserted = inserted || (action.Kind == sessionReconcileInsert && action.SessionID == "instance-B:S-1-new")
		ended = ended || (action.Kind == sessionReconcileEnd && action.SessionID == "instance-A:S-1")
	}
	if !inserted || !ended {
		t.Fatalf("missing insert or end: %+v", actions)
	}
}

// Two open rows sharing one login key cannot be resolved safely; the member is counted, not guessed.
func TestAmbiguousLoginKeyIsCountedNotGuessed(t *testing.T) {
	rows := []policy.Session{
		keyedRow("instance-A:S-1", rotatedLoginKey, reconcileObserved.Add(-30*time.Minute)),
		keyedRow("instance-C:S-1", rotatedLoginKey, reconcileObserved.Add(-20*time.Minute)),
	}
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(keyedMember("instance-B:S-1", rotatedLoginKey)), rows, time.Time{})
	if conflicts != 1 {
		t.Fatalf("conflicts=%d want 1", conflicts)
	}
	for _, action := range actions {
		if action.Kind == sessionReconcileInsert {
			t.Fatalf("ambiguous member inserted: %+v", action)
		}
	}
}

// After the confirmation is applied, replaying the rotated snapshot changes nothing.
func TestInstanceRotationReplayIsIdempotent(t *testing.T) {
	snapshot := snapshotWith(keyedMember("instance-B:S-1", rotatedLoginKey))
	rows := []policy.Session{keyedRow("instance-A:S-1", rotatedLoginKey, reconcileObserved.Add(-30*time.Minute))}
	first, _ := planSnapshotSessionReconcile(snapshot, rows, time.Time{})
	rows = applyReconcileActions(rows, first)
	second, conflicts := planSnapshotSessionReconcile(snapshot, rows, time.Time{})
	if len(second) != 0 || conflicts != 0 {
		t.Fatalf("replay after rotation actions=%+v conflicts=%d", second, conflicts)
	}
}

// The login key must survive the real adapter path, or aliasing never fires in production.
func TestLoginKeyReachesSessionsFromAdapterEvents(t *testing.T) {
	var input, output bytes.Buffer
	at := reconcileObserved.Add(-time.Minute)
	err := json.NewEncoder(&input).Encode(map[string]string{
		"source": reconcileScope.Source, "sensor_id": reconcileScope.SensorID, "campus_id": reconcileScope.CampusID,
		"access_domain": reconcileScope.AccessDomain, "timestamp": at.Format(time.RFC3339Nano), "entity_role": "endpoint",
		"account_id": "acct-1", "session_id": "instance-B:S-1", "source_session_id": "S-1",
		"source_login_generation": "1790820000", "ip": "10.157.2.191", "action": "login",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityadapter.Convert(&input, &output, identityadapter.Options{Source: reconcileScope.Source, SensorID: reconcileScope.SensorID}); err != nil {
		t.Fatal(err)
	}
	var event normalized.Event
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	rows := policyRows([]normalized.Event{event})
	if len(rows) != 1 || rows[0].LoginKey != rotatedLoginKey {
		t.Fatalf("login key lost: rows=%+v", rows)
	}
	if got := loginKeyFromPayload(map[string]any{"source_session_id": "S-1"}); got != "" {
		t.Fatalf("incomplete generation must not produce a key: %q", got)
	}
}

// Rows written before sensor_id was stored carry no sensor. They still belong to the scope
// by source, campus and access domain, so a snapshot confirms them instead of duplicating them.
func TestLegacyRowWithoutSensorMatchesScopeByID(t *testing.T) {
	legacy := eventRow("sess-L", "acct-1", "10.157.2.191", reconcileObserved.Add(-30*time.Minute))
	legacy.SensorID = ""
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(snapshotMember("sess-L", "acct-1", "10.157.2.191")), []policy.Session{legacy}, time.Time{})
	requireOneAction(t, actions, sessionReconcileConfirm, "sess-L")
	if conflicts != 0 {
		t.Fatalf("conflicts=%d", conflicts)
	}
}

// A legacy open row missing from a complete snapshot still ends, so history cannot stay open forever.
func TestLegacyOpenRowWithoutSensorEndsWhenMissing(t *testing.T) {
	legacy := eventRow("sess-M", "acct-6", "10.157.2.60", reconcileObserved.Add(-time.Hour))
	legacy.SensorID = ""
	actions, _ := planSnapshotSessionReconcile(snapshotWith(snapshotMember("sess-other", "acct-other", "10.0.0.250")), []policy.Session{legacy}, time.Time{})
	findAction(t, actions, sessionReconcileEnd, "sess-M")
}

// A row with a different non-empty sensor is a different collector and stays untouched.
func TestRowFromOtherSensorWithSameSourceIsUntouched(t *testing.T) {
	other := eventRow("sess-N", "acct-7", "10.157.2.70", reconcileObserved.Add(-time.Hour))
	other.SensorID = "ncu-other-sensor"
	actions, _ := planSnapshotSessionReconcile(snapshotWith(), []policy.Session{other}, time.Time{})
	if len(actions) != 0 {
		t.Fatalf("other sensor row changed: %+v", actions)
	}
}

// Dual-stack members share one session ID but carry different addresses. One row per session ID
// is the storage contract, so a snapshot must plan one insert, not two statements on the same row.
func TestDualStackMembersPlanOneRowPerSessionID(t *testing.T) {
	first := snapshotMember("sess-D2", "acct-8", "10.157.2.80")
	second := snapshotMember("sess-D2", "acct-8", "2001:db8::80")
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(first, second), nil, time.Time{})
	requireOneAction(t, actions, sessionReconcileInsert, "sess-D2")
	if conflicts != 0 {
		t.Fatalf("conflicts=%d", conflicts)
	}
}

// An empty inventory is not evidence that every session ended: a failed source returns nothing.
// Campus online counts never reach zero, so an empty snapshot ends nothing and confirms nothing.
func TestEmptySnapshotEndsNothing(t *testing.T) {
	rows := []policy.Session{
		eventRow("sess-E1", "acct-9", "10.157.2.90", reconcileObserved.Add(-time.Hour)),
		keyedRow("sess-E2", rotatedLoginKey, reconcileObserved.Add(-time.Hour)),
	}
	actions, conflicts := planSnapshotSessionReconcile(snapshotWith(), rows, time.Time{})
	if len(actions) != 0 || conflicts != 0 {
		t.Fatalf("empty snapshot changed state: actions=%+v conflicts=%d", actions, conflicts)
	}
}
