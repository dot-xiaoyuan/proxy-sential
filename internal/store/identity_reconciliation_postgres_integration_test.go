package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
)

func TestPostgresIdentitySnapshotAtomicReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	source := fmt.Sprintf("snapshot-test-%d", time.Now().UnixNano())
	at := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)
	scope := IdentityScope{Source: source, SensorID: "sensor", CampusID: "campus-east", AccessDomain: "wifi"}
	defer pg.db.ExecContext(context.Background(), `DELETE FROM identity_full_snapshots WHERE source=$1`, source)
	defer pg.db.ExecContext(context.Background(), `DELETE FROM policy_identity_observations WHERE session_id=$1`, source)
	defer pg.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE actor=$1`, "identity-integration:"+source)
	makeSnapshot := func(id string, second int, online bool) IdentitySnapshot {
		snap := IdentitySnapshot{IdentityScope: scope, SnapshotID: id, ObservedAt: at.Add(time.Duration(second) * time.Second), IntervalSeconds: 60, Events: []normalized.Event{}}
		if online {
			e := universityIdentityEvent(source+id, source, "reconcile", snap.ObservedAt.Format(time.RFC3339Nano))
			e.Source = source
			e.Payload["origin"] = source
			e.Observer = map[string]any{"sensor_id": scope.SensorID}
			e.Payload["access_domain"] = scope.AccessDomain
			e.Payload["heartbeat_interval_seconds"] = "60"
			snap.Events = append(snap.Events, e)
		}
		return snap
	}
	first := makeSnapshot("first", 0, true)
	// Concurrent retry of the same immutable inventory creates exactly one commit.
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := pg.CommitIdentitySnapshot(ctx, first)
			results <- created
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	count := 0
	for created := range results {
		if created {
			count++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatalf("created %d snapshots", count)
	}
	changed := makeSnapshot("first", 0, false)
	if _, err = pg.CommitIdentitySnapshot(ctx, changed); !errors.Is(err, ErrIdentitySnapshotConflict) {
		t.Fatalf("conflicting retry accepted: %v", err)
	}
	// Persist out of arrival order, then ingest an older fact after an empty snapshot.
	recovered := makeSnapshot("recovered", 120, true)
	empty := makeSnapshot("empty", 60, false)
	for _, snapshot := range []IdentitySnapshot{recovered, empty} {
		if _, err = pg.CommitIdentitySnapshot(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	late := makeSnapshot("late", 30, true).Events
	late[0].Payload["session_status"] = "heartbeat"
	late[0].Subject["endpoint_id"] = source
	late[0].Subject["mac"] = ""
	defer pg.db.ExecContext(context.Background(), `DELETE FROM identity_ip_mac_history WHERE event_id=$1`, late[0].EventID)
	defer pg.db.ExecContext(context.Background(), `DELETE FROM identity_access_history WHERE event_id=$1`, late[0].EventID)
	defer pg.db.ExecContext(context.Background(), `DELETE FROM account_sessions WHERE session_id=$1`, source)
	defer pg.db.ExecContext(context.Background(), `DELETE FROM endpoint_device_profiles WHERE endpoint_id=$1`, source)
	defer pg.db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, source)
	if err = pg.WriteIdentityEvents(ctx, late); err != nil {
		t.Fatal(err)
	}
	var factCount int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM policy_identity_observations WHERE event_id=$1`, late[0].EventID).Scan(&factCount); err != nil || factCount != 1 {
		t.Fatalf("incremental ingest omitted policy facts: count=%d err=%v", factCount, err)
	}
	readState := func(second int, want string) {
		t.Helper()
		when := at.Add(time.Duration(second) * time.Second)
		all, err := pg.ListPolicySessions(ctx, when)
		if err != nil {
			t.Fatal(err)
		}
		active := []policy.Session{}
		for _, s := range all {
			if s.Source == source && s.State(when) == "active" {
				active = append(active, s)
			}
		}
		if want == "active" && len(active) != 1 || want != "active" && len(active) != 0 {
			t.Fatalf("at %d want %s, active=%+v", second, want, active)
		}
	}
	readState(45, "active")
	readState(90, "ended")
	readState(150, "active")
	readState(300, "unknown")
	states, err := pg.IdentitySources(ctx, at.Add(300*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range states {
		if v.Source == source {
			found = true
			if v.State != "interrupted" || v.SnapshotID != "recovered" {
				t.Fatalf("source health %+v", v)
			}
		}
	}
	if !found {
		t.Fatal("missing source health")
	}
	// Simulate a failure after inserting the snapshot but before transaction commit.
	_, err = pg.db.ExecContext(ctx, `CREATE OR REPLACE FUNCTION identity_snapshot_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor LIKE 'identity-integration:snapshot-test-%' AND NEW.target LIKE '%/fail' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER identity_snapshot_test_failure BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION identity_snapshot_test_failure()`)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.db.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS identity_snapshot_test_failure ON audit_logs; DROP FUNCTION IF EXISTS identity_snapshot_test_failure()`)
	failure := makeSnapshot("fail", 180, false)
	if _, err = pg.CommitIdentitySnapshot(ctx, failure); err == nil {
		t.Fatal("fault injection did not fail")
	}
	var persisted int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM identity_full_snapshots WHERE source=$1 AND snapshot_id='fail'`, source).Scan(&persisted); err != nil || persisted != 0 {
		t.Fatalf("partial snapshot survived rollback: count=%d err=%v", persisted, err)
	}
	if _, err = pg.db.ExecContext(ctx, `DROP TRIGGER identity_snapshot_test_failure ON audit_logs; DROP FUNCTION identity_snapshot_test_failure()`); err != nil {
		t.Fatal(err)
	}
	pg2, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg2.Close()
	if created, err := pg2.CommitIdentitySnapshot(ctx, recovered); err != nil || created {
		t.Fatalf("restart retry not idempotent: %v %v", created, err)
	}
	if created, err := pg2.CommitIdentitySnapshot(ctx, failure); err != nil || !created {
		t.Fatalf("failed transaction not retryable: %v %v", created, err)
	}
}
