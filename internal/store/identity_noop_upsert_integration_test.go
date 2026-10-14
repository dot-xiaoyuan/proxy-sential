package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// A replayed or duplicated event must not rewrite rows with values they already hold.
// PostgreSQL writes a new tuple version, every index entry and the row triggers even when
// the new values equal the old ones, so without the ON CONFLICT ... WHERE guard the field
// re-dirtied the inventory projection and paid a full write for nothing. `xmin` pins the
// row version, which is what the guard is really about — updated_at alone would not prove
// that no work happened.
func TestEntityUpsertSkipsUnchangedRows(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	seen := time.Now().UTC().Truncate(time.Microsecond)
	endpoint := "mac:02:00:00:00:00:9a"
	item := EndpointEntity{EndpointID: endpoint, PrimaryMAC: "02:00:00:00:00:9a", EntityRole: "endpoint", FirstSeen: seen.Add(-time.Hour).Format(time.RFC3339Nano), LastSeen: seen.Format(time.RFC3339Nano), IdentityConfidence: 0.7}
	write := func(entity EndpointEntity) {
		t.Helper()
		tx, err := pg.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = upsertEndpointEntitiesBatch(ctx, tx, []EndpointEntity{entity}); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	version := func() (string, time.Time) {
		t.Helper()
		var xmin string
		var updated time.Time
		if err := pg.db.QueryRowContext(ctx, `SELECT xmin::text,updated_at FROM endpoint_entities WHERE endpoint_id=$1`, endpoint).Scan(&xmin, &updated); err != nil {
			t.Fatal(err)
		}
		return xmin, updated
	}
	write(item)
	firstVersion, firstUpdated := version()

	write(item)
	repeatedVersion, repeatedUpdated := version()
	if repeatedVersion != firstVersion {
		t.Fatalf("replaying an identical event rewrote the row: xmin %s -> %s", firstVersion, repeatedVersion)
	}
	if !repeatedUpdated.Equal(firstUpdated) {
		t.Fatalf("replaying an identical event moved updated_at: %s -> %s", firstUpdated, repeatedUpdated)
	}

	newer := item
	newer.LastSeen = seen.Add(time.Minute).Format(time.RFC3339Nano)
	write(newer)
	advancedVersion, advancedUpdated := version()
	if advancedVersion == firstVersion {
		t.Fatal("an event that advances last_seen did not update the row")
	}
	if !advancedUpdated.After(firstUpdated) {
		t.Fatalf("last_seen advanced but updated_at did not: %s -> %s", firstUpdated, advancedUpdated)
	}
	var lastSeen time.Time
	if err := pg.db.QueryRowContext(ctx, `SELECT last_seen FROM endpoint_entities WHERE endpoint_id=$1`, endpoint).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	wantLastSeen, err := time.Parse(time.RFC3339Nano, newer.LastSeen)
	if err != nil {
		t.Fatal(err)
	}
	if !lastSeen.UTC().Equal(wantLastSeen.UTC()) {
		t.Fatalf("last_seen not advanced: got %s want %s", lastSeen, wantLastSeen)
	}
}

// The same no-op guard covers the other two projection-trigger tables written by this batch
// path. A mis-mirrored predicate here would silently drop real updates, so each guard is
// pinned by row version: identical replay must not write, a real change must.
func TestIdentityHistoryUpsertsSkipUnchangedRows(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	seen := time.Now().UTC().Truncate(time.Microsecond)
	stamp := seen.Format(time.RFC3339Nano)

	accessEvent := "noop-access-" + seen.Format("150405.000000")
	access := IdentityAccessHistory{EventID: accessEvent, EndpointID: "mac:02:00:00:00:00:9b", AccountID: "noop-account", EntityRole: "endpoint", AccessID: "noop-ap", Source: "test", FirstSeen: stamp, LastSeen: stamp, IdentityConfidence: 0.6}
	sessionID := "noop-session-" + seen.Format("150405.000000")
	session := AccountSession{SessionID: sessionID, AccountID: "noop-account", EndpointID: "mac:02:00:00:00:00:9b", IP: "192.0.2.201", Source: "test", StartedAt: stamp, IdentityConfidence: 0.6, RawRef: map[string]any{"sensor_id": "noop-test"}}

	write := func(access IdentityAccessHistory, session AccountSession) {
		t.Helper()
		tx, err := pg.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = insertAccessHistoryBatch(ctx, tx, []IdentityAccessHistory{access}); err != nil {
			t.Fatal(err)
		}
		if err = upsertAccountSessionsBatch(ctx, tx, []AccountSession{session}); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	version := func(table, keyColumn, key string) string {
		t.Helper()
		var xmin string
		if err := pg.db.QueryRowContext(ctx, `SELECT xmin::text FROM `+table+` WHERE `+keyColumn+`=$1`, key).Scan(&xmin); err != nil {
			t.Fatal(err)
		}
		return xmin
	}
	write(access, session)
	accessVersion, sessionVersion := version("identity_access_history", "event_id", accessEvent), version("account_sessions", "session_id", sessionID)

	// Identical replay: neither table may be rewritten, including the policy_metadata
	// statement that runs straight after the session upsert.
	write(access, session)
	if got := version("identity_access_history", "event_id", accessEvent); got != accessVersion {
		t.Fatalf("replaying an identical access event rewrote the row: xmin %s -> %s", accessVersion, got)
	}
	if got := version("account_sessions", "session_id", sessionID); got != sessionVersion {
		t.Fatalf("replaying an identical session rewrote the row: xmin %s -> %s", sessionVersion, got)
	}

	// A real advance must still be applied.
	later := access
	later.LastSeen = seen.Add(time.Minute).Format(time.RFC3339Nano)
	advanced := session
	advanced.SessionStatus = "offline"
	write(later, advanced)
	if got := version("identity_access_history", "event_id", accessEvent); got == accessVersion {
		t.Fatal("an access event that advances last_seen did not update the row")
	}
	if got := version("account_sessions", "session_id", sessionID); got == sessionVersion {
		t.Fatal("a session whose status changed did not update the row")
	}
	var lastSeen time.Time
	if err := pg.db.QueryRowContext(ctx, `SELECT last_seen FROM identity_access_history WHERE event_id=$1`, accessEvent).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	want, err := time.Parse(time.RFC3339Nano, later.LastSeen)
	if err != nil {
		t.Fatal(err)
	}
	if !lastSeen.UTC().Equal(want.UTC()) {
		t.Fatalf("access last_seen not advanced: got %s want %s", lastSeen, want)
	}
	var status string
	if err := pg.db.QueryRowContext(ctx, `SELECT COALESCE(session_status,'') FROM account_sessions WHERE session_id=$1`, sessionID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "offline" {
		t.Fatalf("session_status not applied: got %q", status)
	}
}
