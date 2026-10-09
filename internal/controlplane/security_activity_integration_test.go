package controlplane

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestPostgresSessionActivityDoesNotBlockConcurrentAuthorization(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Path, "/sentinel_acceptance_") {
		t.Fatal("requires an owned sentinel_acceptance_ database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(24)
	token := shortToken(32)
	id := "activity-test-" + shortToken(8)
	if _, err = db.ExecContext(ctx, `INSERT INTO local_users(user_id,username,display_name,role,password_hash,disabled) VALUES($1,$1,'activity test','admin','test-only',false)`, id); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM local_users WHERE user_id=$1`, id)
	if _, err = db.ExecContext(ctx, `INSERT INTO local_auth_sessions(session_hash,user_id,csrf_hash,expires_at,last_seen_at) VALUES($1,$2,'test-only',now()+interval '1 hour',now())`, tokenHash(token), id); err != nil {
		t.Fatal(err)
	}
	a := &authManager{db: db}
	var initial time.Time
	if err = db.QueryRowContext(ctx, `SELECT last_seen_at FROM local_auth_sessions WHERE session_hash=$1`, tokenHash(token)).Scan(&initial); err != nil {
		t.Fatal(err)
	}
	// Hold the activity row lock. Authentication must remain a fresh MVCC read,
	// not queue a write behind this lock for each page/API request.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE local_auth_sessions SET last_seen_at=last_seen_at WHERE session_hash=$1`, tokenHash(token)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan bool, 20)
	start := time.Now()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session, ok := a.currentPostgres(token)
			failures <- !ok || session.User.ID != id
		}()
	}
	wg.Wait()
	close(failures)
	for failed := range failures {
		if failed {
			t.Fatal("concurrent authorization failed")
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("authorization waited on activity row lock: %v", elapsed)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var after time.Time
	if err = db.QueryRowContext(ctx, `SELECT last_seen_at FROM local_auth_sessions WHERE session_hash=$1`, tokenHash(token)).Scan(&after); err != nil || !after.Equal(initial) {
		t.Fatal("fresh requests should not rewrite session activity")
	}
	if _, err = db.ExecContext(ctx, `UPDATE local_auth_sessions SET last_seen_at=now()-interval '2 minutes' WHERE session_hash=$1`, tokenHash(token)); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE local_auth_sessions SET last_seen_at=last_seen_at WHERE session_hash=$1`, tokenHash(token)); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if _, ok := a.currentPostgres(token); !ok {
		t.Fatal("stale activity session should remain authorized")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("stale activity touch blocked authorization")
	}
	for i := 0; i < 20; i++ {
		if _, ok := a.currentPostgres(token); !ok {
			t.Fatal("activity writer must not block additional reads")
		}
	}
	if len(a.activityWrites) != 1 {
		t.Fatal("expected exactly one bounded activity writer")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err = db.QueryRowContext(ctx, `SELECT last_seen_at FROM local_auth_sessions WHERE session_hash=$1`, tokenHash(token)).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if !after.Before(initial) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stale activity timestamp should be refreshed asynchronously")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = db.ExecContext(ctx, `UPDATE local_users SET role='viewer' WHERE user_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if session, ok := a.currentPostgres(token); !ok || session.User.Role != "viewer" {
		t.Fatal("role changes must be visible on the next request")
	}
	if _, err = db.ExecContext(ctx, `UPDATE local_users SET disabled=true WHERE user_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.currentPostgres(token); ok {
		t.Fatal("disabled user remained authorized")
	}
	if _, err = db.ExecContext(ctx, `UPDATE local_users SET disabled=false WHERE user_id=$1;`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE local_auth_sessions SET expires_at=now()-interval '1 second' WHERE session_hash=$1`, tokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.currentPostgres(token); ok {
		t.Fatal("expired session remained authorized")
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM local_auth_sessions WHERE session_hash=$1`, tokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.currentPostgres(token); ok {
		t.Fatal("revoked session remained authorized")
	}
}
