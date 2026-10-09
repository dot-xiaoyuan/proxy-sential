package store

import (
	"context"
	"testing"
	"time"
)

func TestActivityV3FreshnessReadOnlyPostgres(t *testing.T) {
	s := activityV3PrivatePostgres(t)
	ctx := context.Background()
	if _, err := s.ensureActivityV3Cutover(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := s.pg.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A session-wide guard applies to every connection used by the GET path.
	s.pg.db.SetMaxOpenConns(1)
	if _, err = conn.ExecContext(ctx, "SET default_transaction_read_only=on"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	t.Cleanup(func() { s.pg.db.Exec("SET default_transaction_read_only=off") })
	if _, err = s.activityV3Freshness(ctx, time.Hour, ""); err != nil {
		t.Fatalf("statistics GET attempted initialization writes: %v", err)
	}
}

func TestActivityV3FreshnessDoesNotWaitForWorkerLockPostgres(t *testing.T) {
	s := activityV3PrivatePostgres(t)
	ctx := context.Background()
	if _, err := s.ensureActivityV3Cutover(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=state WHERE name='activity-v3'`); err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err = s.activityV3Freshness(readCtx, time.Hour, ""); err != nil {
		t.Fatalf("statistics GET blocked on worker write: %v", err)
	}
}
