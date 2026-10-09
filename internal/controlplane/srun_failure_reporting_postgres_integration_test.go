package controlplane

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestSRunFailureReportingNativeCancellationAndLock(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, srunOperationOrderKey{}, int64(1))
	var name string
	if err = db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(name) {
		t.Fatal("dedicated acceptance database required")
	}
	for _, stmt := range []string{
		`CREATE TABLE srun4k_integrations(connector_id text PRIMARY KEY,connection_state text,last_error text,last_tested_at timestamptz,last_synced_at timestamptz,event_channel_state text,updated_at timestamptz,last_test_result_order bigint NOT NULL DEFAULT 0,last_sync_result_order bigint NOT NULL DEFAULT 0,last_health_result_order bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE audit_logs(audit_id text PRIMARY KEY,actor text,action text,target text,outcome text,created_at timestamptz)`,
		`INSERT INTO srun4k_integrations VALUES('one','healthy','','2026-09-30 00:00:00Z','2026-09-30 01:00:00Z','waiting',now())`,
	} {
		if _, err = db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{operations: &operationsState{db: db}, reader: configuredProbeAudit{db: db}}
	t.Run("cancelled request still reports failure", func(t *testing.T) {
		parent := context.WithValue(ctx, sessionContextKey{}, Session{User: User{ID: "isolated-operator"}})
		cancelled, stop := context.WithCancel(parent)
		stop()
		s.recordSRunFailure(cancelled, "one", "redis: isolated read failed")
		var state, message, eventState string
		var tested, synced time.Time
		if err = db.QueryRowContext(ctx, `SELECT connection_state,last_error,last_tested_at,last_synced_at,event_channel_state FROM srun4k_integrations WHERE connector_id='one'`).Scan(&state, &message, &tested, &synced, &eventState); err != nil {
			t.Fatal(err)
		}
		if state != "failed" || message != "redis: isolated read failed" || !tested.After(time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)) || !synced.Equal(time.Date(2026, 9, 30, 1, 0, 0, 0, time.UTC)) || eventState != "waiting" {
			t.Fatalf("failure not durable or successful-sync/event state modified: state=%s message=%s tested=%s synced=%s event=%s", state, message, tested, synced, eventState)
		}
		var count int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE actor='isolated-operator' AND action='integration.srun4k.test' AND outcome='failed'`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("failure audit count=%d err=%v", count, err)
		}
	})
	t.Run("sync failure preserves test and success clocks", func(t *testing.T) {
		var beforeTest, beforeSync time.Time
		if err = db.QueryRowContext(ctx, `SELECT last_tested_at,last_synced_at FROM srun4k_integrations WHERE connector_id='one'`).Scan(&beforeTest, &beforeSync); err != nil {
			t.Fatal(err)
		}
		s.recordSRunOperationFailure(ctx, "one", "isolated catalog read failed", "integration.srun4k.sync")
		var afterTest, afterSync time.Time
		var state, message, eventState string
		if err = db.QueryRowContext(ctx, `SELECT connection_state,last_error,last_tested_at,last_synced_at,event_channel_state FROM srun4k_integrations WHERE connector_id='one'`).Scan(&state, &message, &afterTest, &afterSync, &eventState); err != nil {
			t.Fatal(err)
		}
		if state != "failed" || message != "isolated catalog read failed" || !afterTest.Equal(beforeTest) || !afterSync.Equal(beforeSync) || eventState != "waiting" {
			t.Fatal("sync failure overwrote connection-test, successful-sync, or event-channel metadata")
		}
		var count int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE action='integration.srun4k.sync' AND outcome='failed'`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("sync failure audit count=%d err=%v", count, err)
		}
	})

	t.Run("blocked state update has finite reporting budget", func(t *testing.T) {
		if _, err = db.ExecContext(ctx, `UPDATE srun4k_integrations SET connection_state='healthy',last_error='' WHERE connector_id='one'`); err != nil {
			t.Fatal(err)
		}
		lock, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback()
		if _, err = lock.ExecContext(ctx, `SELECT connector_id FROM srun4k_integrations WHERE connector_id='one' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		started := time.Now()
		go func() {
			defer close(done)
			s.recordSRunFailure(context.WithValue(context.Background(), srunOperationOrderKey{}, int64(1)), "one", "blocked isolated report")
		}()
		bounded := false
		select {
		case <-done:
			bounded = true
			t.Logf("blocked failure report returned in %s", time.Since(started))
		case <-time.After(4 * time.Second):
			t.Error("failure report waited without a bounded cleanup deadline")
		}
		// Always release the owned lock, including old-code regression failure.
		if err = lock.Rollback(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("report did not exit after isolated lock released")
		}
		if bounded {
			var state string
			if err = db.QueryRowContext(ctx, `SELECT connection_state FROM srun4k_integrations WHERE connector_id='one'`).Scan(&state); err != nil || state != "healthy" {
				t.Fatalf("timed-out write claimed success: state=%s err=%v", state, err)
			}
		}
	})
	t.Run("blocked audit shares finite report budget", func(t *testing.T) {
		var before int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		lock, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback()
		if _, err = lock.ExecContext(ctx, `LOCK audit_logs IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		started := time.Now()
		go func() {
			defer close(done)
			s.recordSRunFailure(context.WithValue(context.Background(), srunOperationOrderKey{}, int64(1)), "one", "isolated audit lock")
		}()
		select {
		case <-done:
			t.Logf("blocked audit report returned in %s", time.Since(started))
		case <-time.After(4 * time.Second):
			t.Error("audit write escaped the report deadline")
		}
		if err = lock.Rollback(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("audit did not exit after owned lock released")
		}
		var state string
		var after int
		if err = db.QueryRowContext(ctx, `SELECT connection_state FROM srun4k_integrations WHERE connector_id='one'`).Scan(&state); err != nil || state != "failed" {
			t.Fatalf("failure state=%s err=%v", state, err)
		}
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs`).Scan(&after); err != nil || after != before {
			t.Fatalf("timed-out audit claimed persistence: before=%d after=%d err=%v", before, after, err)
		}
	})

}
