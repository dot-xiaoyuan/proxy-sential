package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/srunapi"
)

// Validate the database before invoking a fixture which applies migrations.
func srunIsolatedReplayDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var name string
	err = db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&name)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(name) {
		t.Fatal("dedicated acceptance database required before migration")
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func srunIsolatedReplayServer(t *testing.T) (*Server, Session) {
	t.Helper()
	srunIsolatedReplayDB(t).Close()
	return taskIntegrationServer(t)
}

func TestSRunGroupNativeSnapshotOrdering(t *testing.T) {
	s, actor := srunIsolatedReplayServer(t)
	ctx := context.WithValue(context.Background(), sessionContextKey{}, actor)
	now := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	newer := now.Add(time.Second)
	for _, tc := range []string{"older_nonempty_after_newer", "older_after_empty", "empty_after_empty", "equal_time_conflict", "equal_time_permutation_retry", "independent_sources", "newer_replaces_removed_groups"} {
		t.Run(tc, func(t *testing.T) {
			source := "group-order-" + tc + "-" + shortToken(12)
			first := []srunapi.Group{{ID: "2", Name: "new group", ParentID: "1", Path: "/new"}}
			second := []srunapi.Group{{ID: "1", Name: "old group", Path: "/old"}}
			at1, at2 := newer, now
			switch tc {
			case "older_after_empty", "empty_after_empty":
				first = []srunapi.Group{}
			case "equal_time_conflict":
				at2 = newer
			case "equal_time_permutation_retry":
				first = append(first, second...)
				second = []srunapi.Group{first[1], first[0]}
				at2 = newer
			case "newer_replaces_removed_groups":
				at1, at2 = now, newer
			}
			if tc == "empty_after_empty" {
				second = []srunapi.Group{}
			}
			if err := s.commitSRunGroups(ctx, source, first, at1); err != nil {
				t.Fatal(err)
			}
			target := source
			if tc == "independent_sources" {
				target += "-other"
			}
			err := s.commitSRunGroups(ctx, target, second, at2)
			rejected := tc == "older_nonempty_after_newer" || tc == "older_after_empty" || tc == "empty_after_empty" || tc == "equal_time_conflict"
			if rejected && err == nil {
				t.Fatal("out-of-order or conflicting group snapshot accepted")
			}
			if !rejected && err != nil {
				t.Fatal(err)
			}
			rows, err := s.operations.db.QueryContext(ctx, `SELECT group_id,name FROM srun4k_group_catalog WHERE source=$1 AND active ORDER BY group_id`, source)
			if err != nil {
				t.Fatal(err)
			}
			current := map[string]string{}
			for rows.Next() {
				var id, name string
				if err = rows.Scan(&id, &name); err != nil {
					t.Fatal(err)
				}
				current[id] = name
			}
			rows.Close()
			expected := first
			if tc == "newer_replaces_removed_groups" {
				expected = second
			}
			if len(current) != len(expected) {
				t.Fatalf("current groups changed: %v want %+v", current, expected)
			}
			for _, group := range expected {
				if current[group.ID] != group.Name {
					t.Fatalf("current groups changed: %v want %+v", current, expected)
				}
			}
		})
	}
}

func TestSRunGroupNativeAtomicAuditAndConcurrentPublication(t *testing.T) {
	s, actor := srunIsolatedReplayServer(t)
	ctx := context.WithValue(context.Background(), sessionContextKey{}, actor)
	db := s.operations.db
	now := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	source := "group-atomic-" + shortToken(12)
	if err := s.commitSRunGroups(ctx, source, []srunapi.Group{{ID: "first", Name: "original"}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE FUNCTION reject_group_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated group audit rejection'; END $$; CREATE TRIGGER reject_group_audit BEFORE INSERT ON audit_logs FOR EACH ROW WHEN (NEW.action='integration.srun4k.groups') EXECUTE FUNCTION reject_group_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := s.commitSRunGroups(ctx, source, []srunapi.Group{}, now.Add(time.Second)); err == nil {
		t.Fatal("unaudited directory accepted")
	}
	if _, err := db.ExecContext(ctx, `DROP TRIGGER reject_group_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_group_snapshots WHERE source=$1`, source).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit rejection left snapshot: %d %v", count, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_group_catalog WHERE source=$1 AND active AND name='original'`, source).Scan(&count); err != nil || count != 1 {
		t.Fatal("audit rejection changed current catalog")
	}
	// Both writers reach the same source lock, then race for publication. The
	// final directory must be the newer observation regardless of wake order.
	held, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	if _, err = held.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7142))`, source); err != nil {
		t.Fatal(err)
	}
	olderDone, newerDone := make(chan error, 1), make(chan error, 1)
	go func() {
		olderDone <- s.commitSRunGroups(ctx, source, []srunapi.Group{{ID: "older", Name: "older"}}, now.Add(time.Second))
	}()
	go func() {
		newerDone <- s.commitSRunGroups(ctx, source, []srunapi.Group{{ID: "newer", Name: "newer"}}, now.Add(2*time.Second))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=((hashtextextended($1,7142)>>32)&4294967295)::oid AND objid=(hashtextextended($1,7142)&4294967295)::oid AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`, source).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("writers did not reach source lock: %d", count)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A separate source must remain able to publish while this source waits.
	if err = s.commitSRunGroups(ctx, source+"-independent", []srunapi.Group{}, now); err != nil {
		t.Fatal(err)
	}
	if err = held.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = <-newerDone; err != nil {
		t.Fatal("newer writer:", err)
	}
	if err = <-olderDone; err != nil && !errors.Is(err, errSRunGroupSnapshotSuperseded) {
		t.Fatal("older writer:", err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_group_catalog WHERE source=$1 AND active AND group_id='newer'`, source).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent publication lost newer group")
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_group_catalog WHERE source=$1 AND active`, source).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent publication mixed two directories")
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_group_snapshots WHERE source=$1`, source).Scan(&count); err != nil || count != 3 {
		t.Fatalf("raw observations not retained: %d %v", count, err)
	}
}
