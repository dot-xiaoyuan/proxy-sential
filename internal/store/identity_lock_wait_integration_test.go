package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// The identity write lock is held almost continuously by the domain worker, so a live lane
// that skips instead of waiting never runs. The field measured the identity materializer's
// live cursor frozen while endpoint_entities stopped advancing, with no error recorded.
// awaitIdentityWriteLock must therefore actually wait for the lock, not skip it, and must
// still return control to the caller once its budget is spent.
func TestAwaitIdentityWriteLockWaitsThenGivesUp(t *testing.T) {
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

	// Free lock: the first attempt succeeds without spending the budget.
	free, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if locked, err := awaitIdentityWriteLock(ctx, free, time.Second); err != nil || !locked {
		free.Rollback()
		t.Fatalf("free lock was not acquired: locked=%v err=%v", locked, err)
	}
	free.Rollback()

	blocker, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('proxy-sentinel-identity-write', 7137))`); err != nil {
		t.Fatal(err)
	}
	waiting, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer waiting.Rollback()
	started := time.Now()
	locked, err := awaitIdentityWriteLock(ctx, waiting, 400*time.Millisecond)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("waiting for a held lock failed: %v", err)
	}
	if locked {
		t.Fatal("reported the identity write lock while another writer held it")
	}
	if elapsed < 300*time.Millisecond {
		t.Fatalf("gave up after %s instead of waiting out its budget", elapsed)
	}
	waiting.Rollback()
	if err = blocker.Rollback(); err != nil {
		t.Fatal(err)
	}

	// Released: the lane must make progress instead of starving.
	after, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Rollback()
	if locked, err := awaitIdentityWriteLock(ctx, after, time.Second); err != nil || !locked {
		t.Fatalf("released lock was not acquired: locked=%v err=%v", locked, err)
	}
}
