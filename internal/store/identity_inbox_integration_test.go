package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func inboxTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	if _, err := ApplyPostgresMigrations(context.Background(), dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	return pg
}
func inboxEvent(scope IdentityScope, id, sid, ip, status string, at time.Time) normalized.Event {
	return normalized.Event{EventID: id, Type: "identity", Timestamp: at.UTC().Format(time.RFC3339Nano), Source: scope.Source, Observer: map[string]any{"sensor_id": scope.SensorID}, Subject: map[string]any{"entity_role": "endpoint", "account_id": "student", "ip": ip, "campus_id": scope.CampusID}, Payload: map[string]any{"campus_id": scope.CampusID, "origin": scope.Source, "session_id": sid, "session_status": status, "access_domain": scope.AccessDomain}}
}

// snapshotEvent is one complete-snapshot member: status reconcile, heartbeat equal to the interval.
func snapshotEvent(scope IdentityScope, id, sid, ip string, at time.Time, interval int) normalized.Event {
	event := inboxEvent(scope, id, sid, ip, "reconcile", at)
	event.Payload["heartbeat_interval_seconds"] = strconv.Itoa(interval)
	event.Payload["reconcile_interval_seconds"] = strconv.Itoa(interval)
	return event
}

func TestIdentityInboxDurabilityFencingAndCounters(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "test-inbox", SensorID: fmt.Sprintf("inbox-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	at := time.Now().UTC().Truncate(time.Microsecond)
	events := []normalized.Event{inboxEvent(scope, "login-v4", "generation-1", "192.0.2.1", "start", at), inboxEvent(scope, "login-v6", "generation-1", "2001:db8::1", "start", at), inboxEvent(scope, "logout-v4", "generation-1", "192.0.2.1", "stop", at.Add(time.Second))}
	// A committed receipt can be lost in transport; duplicate input returns the identical receipt.
	receipt, err := pg.acceptIdentityBatch(ctx, key+"-1", "hash", scope, events, 3)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := pg.acceptIdentityBatch(ctx, key+"-1", "hash", scope, events, 3)
	if err != nil || receipt != retry {
		t.Fatalf("duplicate receipt: %+v %v", retry, err)
	}
	if _, err = pg.acceptIdentityBatch(ctx, key+"-1", "different", scope, events, 3); !errors.Is(err, ErrIdentityBatchConflict) {
		t.Fatalf("collision: %v", err)
	}
	work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Crash after claim: another worker cannot steal a live lease. After expiry it
	// receives a new generation and the old claimant cannot commit.
	if _, err = pg.claimIdentityInbox(ctx, scope.SensorID, 2); err == nil {
		t.Fatal("double claim")
	}
	if _, err = pg.db.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET lease_until=now()-interval '1 second' WHERE scope_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	replacement, err := pg.claimIdentityInbox(ctx, scope.SensorID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); !errors.Is(err, ErrIdentityLeaseExpired) {
		t.Fatalf("stale claimant committed: %v", err)
	}
	if err = pg.applyIdentityInbox(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	check := func(accounts, sessions, pending int) {
		t.Helper()
		var a, s, p int
		if err := pg.db.QueryRowContext(ctx, `SELECT accounts,sessions,pending_records FROM identity_pipeline_scopes WHERE scope_key=$1`, key).Scan(&a, &s, &p); err != nil {
			t.Fatal(err)
		}
		if a != accounts || s != sessions || p != pending {
			t.Fatalf("counts %d %d %d expected %d %d %d", a, s, p, accounts, sessions, pending)
		}
	}
	// Account and session totals are published with complete snapshots; applies never change them.
	check(0, 0, 1)
	// A crash after commit and retry cannot count twice.
	if err = pg.applyIdentityInbox(ctx, replacement); !errors.Is(err, ErrIdentityLeaseExpired) {
		t.Fatalf("repeat commit: %v", err)
	}
	work, err = pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	check(0, 0, 0)
	next := []normalized.Event{events[0], events[1], inboxEvent(scope, "logout-v6", "generation-1", "2001:db8::1", "stop", at.Add(time.Second)), inboxEvent(scope, "equal-login", "generation-1", "2001:db8::1", "start", at.Add(time.Second)), inboxEvent(scope, "new-generation", "generation-2", "192.0.2.1", "start", at.Add(2*time.Second))}
	if _, err = pg.acceptIdentityBatch(ctx, key+"-2", "hash2", scope, next, len(next)); err != nil {
		t.Fatal(err)
	}
	work, err = pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	check(0, 0, 0)
}

func TestSnapshotCommitPublishesCountsForwardOnly(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "publication", SensorID: fmt.Sprintf("publication-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	snap := IdentitySnapshot{IdentityScope: scope, SnapshotID: "first", ObservedAt: at, IntervalSeconds: 60, Events: []normalized.Event{snapshotEvent(scope, key+"base", "old-session", "192.0.2.1", at, 60)}}
	if _, err := pg.CommitIdentitySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil {
		t.Fatal(err)
	}
	if *summary.Accounts != 1 || *summary.Sessions != 1 || summary.CalibrationState != "completed" || !summary.SnapshotAt.Equal(at) {
		t.Fatalf("commit did not publish: %+v", summary)
	}
	empty := snap
	empty.SnapshotID = "empty"
	empty.ObservedAt = at.Add(10 * time.Second)
	empty.Events = nil
	if _, err = pg.CommitIdentitySnapshot(ctx, empty); err != nil {
		t.Fatal(err)
	}
	// Replaying the older snapshot is idempotent and cannot move the publication backwards.
	if _, err = pg.CommitIdentitySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	summary, err = ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil {
		t.Fatal(err)
	}
	if *summary.Accounts != 0 || *summary.Sessions != 0 || !summary.SnapshotAt.Equal(empty.ObservedAt) {
		t.Fatalf("old snapshot replaced newer publication: %+v", summary)
	}
	// Incremental facts never change the published totals.
	events := []normalized.Event{inboxEvent(scope, key+"new", "new-session", "192.0.2.2", "start", at.Add(time.Second))}
	if _, err = pg.acceptIdentityBatch(ctx, key+"late", "late-hash", scope, events, len(events)); err != nil {
		t.Fatal(err)
	}
	work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	summary, err = ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil || *summary.Sessions != 0 {
		t.Fatalf("apply changed published totals: %+v %v", summary, err)
	}
}

func TestIdentityInboxCapacityAndScopeIsolation(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "scope-test", SensorID: fmt.Sprintf("scope-%d", time.Now().UnixNano()), CampusID: "first", AccessDomain: "d"}
	for _, campus := range []string{"first", "second"} {
		scope.CampusID = campus
		key := IdentityScopeKey(scope)
		event := inboxEvent(scope, key+"event", "same-session", "192.0.2.1", "start", time.Now().UTC())
		if _, err := pg.acceptIdentityBatch(ctx, key+"batch", "hash-"+campus, scope, []normalized.Event{event}, 1); err != nil {
			t.Fatal(err)
		}
		work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
		if err != nil {
			t.Fatal(err)
		}
		if err = pg.applyIdentityInbox(ctx, work); err != nil {
			t.Fatal(err)
		}
		summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
		if err != nil || *summary.Accounts != 1 || *summary.Sessions != 1 {
			t.Fatalf("scope mixed: %+v %v", summary, err)
		}
	}
	key := IdentityScopeKey(scope)
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET pending_records=1000000 WHERE scope_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.acceptIdentityBatch(ctx, key+"overflow", "other", scope, []normalized.Event{inboxEvent(scope, key+"more", "s", "192.0.2.2", "start", time.Now().UTC())}, 1); !errors.Is(err, ErrIdentityInboxFull) {
		t.Fatalf("capacity did not reject: %v", err)
	}
	var count int
	if err := pg.db.QueryRowContext(ctx, `SELECT count(*) FROM identity_ingest_batches WHERE batch_id=$1`, key+"overflow").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected batch was persisted: %d %v", count, err)
	}
}

func TestIdentityAcceptanceDoesNotWaitForAuthorityRowWrites(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "contention", SensorID: fmt.Sprintf("contention-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	stamp := time.Now().UTC()
	event := inboxEvent(scope, key+"event", "session", "192.0.2.1", "start", stamp)
	if _, err := pg.acceptIdentityBatch(ctx, key+"one", "one", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	event.EventID = key + "update"
	event.Timestamp = stamp.Add(time.Second).Format(time.RFC3339Nano)
	if _, err = pg.acceptIdentityBatch(ctx, key+"two", "two", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	work, err = pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `SELECT * FROM identity_current_addresses WHERE scope_key=$1 FOR UPDATE`, key); err != nil {
		t.Fatal(err)
	}
	applyCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- pg.applyIdentityInbox(applyCtx, work) }()
	// Wait until the authority transaction reaches the blocked address write.
	deadline := time.Now().Add(time.Second)
	for {
		var waiting bool
		if err = pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%identity_apply_address%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authority did not reach injected lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	acceptCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	event.EventID = key + "next"
	event.Timestamp = stamp.Add(2 * time.Second).Format(time.RFC3339Nano)
	if _, err = pg.acceptIdentityBatch(acceptCtx, key+"three", "three", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatalf("acceptance blocked by authority: %v", err)
	}
	if _, err = pg.db.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET lease_until=now()-interval '1 second' WHERE scope_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	replacement, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	blocker.Rollback()
	if err = <-done; !errors.Is(err, ErrIdentityLeaseExpired) {
		t.Fatalf("in-flight expired worker committed: %v", err)
	}
	if err = pg.applyIdentityInbox(ctx, replacement); err != nil {
		t.Fatal(err)
	}

	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil || summary.PendingRecords != 1 || summary.OldestPendingAt == nil {
		t.Fatalf("concurrent progress lost: %+v %v", summary, err)
	}
}

func TestIdentityInboxCombinesAdjacentBatchesWithoutLosingPartialProgress(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "combined", SensorID: fmt.Sprintf("combine-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	at := time.Now().UTC().Truncate(time.Microsecond)
	n := 0
	for batch, count := range []int{2, 2, 1} {
		events := []normalized.Event{}
		for i := 0; i < count; i++ {
			n++
			events = append(events, inboxEvent(scope, fmt.Sprintf("%s-event-%d", key, n), fmt.Sprintf("s%d", n), fmt.Sprintf("192.0.2.%d", n), "start", at))
		}
		if _, err := pg.acceptIdentityBatch(ctx, fmt.Sprintf("%s-batch-%d", key, batch), fmt.Sprint(batch), scope, events, count); err != nil {
			t.Fatal(err)
		}
	}
	first, err := pg.claimIdentityInbox(ctx, scope.SensorID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 3 || len(first.Batches) != 2 {
		t.Fatalf("not combined: %+v", first.Batches)
	}
	if err = pg.applyIdentityInbox(ctx, first); err != nil {
		t.Fatal(err)
	}
	var sequence, pending int
	if err = pg.db.QueryRowContext(ctx, `SELECT processed_sequence,pending_records FROM identity_pipeline_scopes WHERE scope_key=$1`, key).Scan(&sequence, &pending); err != nil || sequence != 1 || pending != 2 {
		t.Fatalf("partial progress %d %d %v", sequence, pending, err)
	}
	second, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) != 2 || second.Offset != 1 {
		t.Fatalf("partial retry lost offset: %+v", second.Batches)
	}
	if err = pg.applyIdentityInbox(ctx, second); err != nil {
		t.Fatal(err)
	}
	var sessions, applied int
	if err = pg.db.QueryRowContext(ctx, `SELECT processed_sequence,pending_records,sessions,(SELECT count(*) FROM identity_applied_events WHERE scope_key=$1) FROM identity_pipeline_scopes WHERE scope_key=$1`, key).Scan(&sequence, &pending, &sessions, &applied); err != nil || sequence != 3 || pending != 0 || sessions != 5 || applied != 5 {
		t.Fatalf("final progress %d %d %d %d %v", sequence, pending, sessions, applied, err)
	}
}

func TestIdentityBacklogDefersDerivedWork(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "priority", SensorID: fmt.Sprintf("priority-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	event := inboxEvent(scope, key+"event", "s", "192.0.2.1", "start", time.Now().UTC())
	if _, err := pg.acceptIdentityBatch(ctx, key+"batch", "hash", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET oldest_pending_at=now()-interval '10 seconds' WHERE scope_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	pg.sensorID = scope.SensorID
	db := &DBStore{pg: pg}
	if !db.deferIdentityDerivedWork(ctx) {
		t.Fatal("historical writes were allowed ahead of current identity")
	}
	// Another sensor's materializer must not stall behind this inbox.
	other := &PostgresStore{db: pg.db, sensorID: scope.SensorID + "-other"}
	if (&DBStore{pg: other}).deferIdentityDerivedWork(ctx) {
		t.Fatal("an unrelated sensor was paused by another inbox backlog")
	}
	var pending int
	if err := pg.db.QueryRowContext(ctx, `SELECT pending_records FROM identity_pipeline_scopes WHERE scope_key=$1`, key).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("priority check changed responsibility", err)
	}
}

func TestConflictingSnapshotRetainsPublishedVersion(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "conflict", SensorID: fmt.Sprintf("conflict-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	first := snapshotEvent(scope, "base", "session", "192.0.2.1", at, 60)
	snap := IdentitySnapshot{IdentityScope: scope, SnapshotID: "good", ObservedAt: at, IntervalSeconds: 60, Events: []normalized.Event{first}}
	if _, err := pg.CommitIdentitySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	later := at.Add(time.Second)
	again := snapshotEvent(scope, "base-again", "session", "192.0.2.1", later, 60)
	second := snapshotEvent(scope, "conflict", "session", "192.0.2.2", later, 60)
	second.Subject["account_id"] = "different-account"
	conflicting := IdentitySnapshot{IdentityScope: scope, SnapshotID: "conflicting", ObservedAt: later, IntervalSeconds: 60, Events: []normalized.Event{again, second}}
	if _, err := pg.CommitIdentitySnapshot(ctx, conflicting); err != nil {
		t.Fatal(err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil || summary.Accounts == nil || *summary.Accounts != 1 || *summary.Sessions != 1 || !summary.SnapshotAt.Equal(at) || summary.CalibrationState != "failed" {
		t.Fatalf("published version lost: %+v %v", summary, err)
	}
}

func TestIdentityInboxWaitsForBriefSummaryWriter(t *testing.T) {
	pg := inboxTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scope := IdentityScope{Source: "summary-contention", SensorID: fmt.Sprintf("summary-contention-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	event := inboxEvent(scope, key, "session", "192.0.2.1", "start", time.Now())
	if _, err := pg.acceptIdentityBatch(ctx, key, "hash", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	blocker, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET heartbeat_at=now() WHERE scope_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		w, e := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
		if e == nil {
			e = pg.applyIdentityInbox(ctx, w)
		}
		done <- e
	}()
	select {
	case e := <-done:
		t.Fatalf("live work mistaken for idle during brief summary lock: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil || summary.PendingRecords != 0 {
		t.Fatalf("progress not published: %+v %v", summary, err)
	}
}
