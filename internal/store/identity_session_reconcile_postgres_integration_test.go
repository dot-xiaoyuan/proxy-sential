package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

// Runs only with PROXY_SENTINEL_TEST_POSTGRES_DSN set. It exercises the commit path end to end:
// insert, instance rotation without duplication, end on absence, replay, and a new login generation.
func TestPostgresSnapshotReconcileInsertsRotatesAndEnds(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	source := fmt.Sprintf("reconcile-test-%d", time.Now().UnixNano())
	scope := IdentityScope{Source: source, SensorID: "sensor-r", CampusID: "campus-r", AccessDomain: "wifi-r"}
	cleanup := func() {
		pg.db.ExecContext(context.Background(), `DELETE FROM account_sessions WHERE source=$1`, source)
		pg.db.ExecContext(context.Background(), `DELETE FROM identity_full_snapshots WHERE source=$1`, source)
		pg.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE actor=$1`, "identity-integration:"+source)
	}
	cleanup()
	defer cleanup()

	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	at := func(offset time.Duration) time.Time { return base.Add(offset) }
	// member builds one snapshot member whose timestamp is the snapshot time, as the commit requires.
	member := func(sessionID, loginGeneration, ip string, observed time.Time) normalized.Event {
		return normalized.Event{
			SchemaVersion: "v1", EventID: "reconcile-" + sessionID + "-" + observed.Format("150405"), Source: source, SourceEventType: "identity",
			Type: "identity", Timestamp: observed.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": scope.SensorID},
			Subject: map[string]any{"ip": ip, "mac": "02:00:00:00:00:99", "endpoint_id": "mac:02:00:00:00:00:99", "account_id": "acct-r", "entity_role": "endpoint"},
			Payload: map[string]any{
				"origin": source, "session_id": sessionID, "session_status": "reconcile", "action": "reconcile",
				"source_session_id": "S-1", "source_login_generation": loginGeneration,
				"campus_id": scope.CampusID, "access_domain": scope.AccessDomain,
				"heartbeat_interval_seconds": "60", "reconcile_interval_seconds": "60",
			},
			Confidence: 0.9,
		}
	}
	snapshot := func(id string, observed time.Time, members ...normalized.Event) IdentitySnapshot {
		return IdentitySnapshot{IdentityScope: scope, SnapshotID: id, ObservedAt: observed, IntervalSeconds: 60, Events: members}
	}
	row := func(sessionID string) (status, loginKey, sensor string, ended sql.NullTime, confirmed string) {
		err := pg.db.QueryRowContext(ctx, `SELECT session_status, login_key, sensor_id, ended_at, COALESCE(policy_metadata->>'last_confirmed_at','') FROM account_sessions WHERE session_id=$1`, sessionID).Scan(&status, &loginKey, &sensor, &ended, &confirmed)
		if err != nil {
			t.Fatalf("row %s: %v", sessionID, err)
		}
		return
	}
	count := func() int {
		var n int
		if err := pg.db.QueryRowContext(ctx, `SELECT count(*) FROM account_sessions WHERE source=$1`, source).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// 1. First snapshot: the member has no row, so a reconcile row is inserted.
	s1 := snapshot("s1", at(0), member("inst-A:S-1", "1790820000", "10.157.2.191", at(0)))
	if _, err := pg.CommitIdentitySnapshot(ctx, s1); err != nil {
		t.Fatal(err)
	}
	status, loginKey, sensor, ended, _ := row("inst-A:S-1")
	if status != "reconcile" || loginKey != "S-1|1790820000" || sensor != scope.SensorID || ended.Valid {
		t.Fatalf("insert wrong: status=%s key=%s sensor=%s ended=%v", status, loginKey, sensor, ended)
	}

	// 2. Redis restarted: same login under a new run_id. Confirm the existing row; do not duplicate.
	s2 := snapshot("s2", at(time.Minute), member("inst-B:S-1", "1790820000", "10.157.2.191", at(time.Minute)))
	if _, err := pg.CommitIdentitySnapshot(ctx, s2); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 1 {
		t.Fatalf("rotation duplicated the login: rows=%d", n)
	}
	_, _, _, ended, confirmed := row("inst-A:S-1")
	if ended.Valid || confirmed != at(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("rotation did not confirm: ended=%v confirmed=%s", ended, confirmed)
	}

	// 3. An empty snapshot is not evidence of absence: the open login must stay open.
	if _, err := pg.CommitIdentitySnapshot(ctx, snapshot("s3", at(2*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ended, _ := row("inst-A:S-1"); ended.Valid {
		t.Fatal("empty snapshot ended a session")
	}

	// 3b. A non-empty complete snapshot without the login ends it at that snapshot's time.
	s3b := snapshot("s3b", at(3*time.Minute), member("inst-D:S-9", "1790840000", "10.157.2.99", at(3*time.Minute)))
	if _, err := pg.CommitIdentitySnapshot(ctx, s3b); err != nil {
		t.Fatal(err)
	}
	status, _, _, ended, _ = row("inst-A:S-1")
	if !ended.Valid || !ended.Time.Equal(at(3*time.Minute)) || status != "stop" {
		t.Fatalf("absence did not end: status=%s ended=%v", status, ended)
	}

	// 4. Replaying the same snapshot changes nothing.
	if _, err := pg.CommitIdentitySnapshot(ctx, s3b); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 2 {
		t.Fatalf("replay changed rows=%d want 2", n)
	}

	// 5. A new login generation on the same source session is a new login, not a rotation.
	s4 := snapshot("s4", at(4*time.Minute), member("inst-B:S-2", "1790830000", "10.157.2.191", at(4*time.Minute)))
	if _, err := pg.CommitIdentitySnapshot(ctx, s4); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 3 {
		t.Fatalf("new login rows=%d want 3", n)
	}
	if _, _, _, ended, _ := row("inst-B:S-2"); ended.Valid {
		t.Fatal("new login inserted as ended")
	}
}
