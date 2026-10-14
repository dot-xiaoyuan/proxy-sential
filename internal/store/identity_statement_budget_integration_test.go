package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestIdentityWriteBudgetEnforcedByPostgres(t *testing.T) {
	pg := inboxTestStore(t)
	tx, err := pg.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	budget, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err = lockIdentityWrite(budget, tx); err != nil {
		t.Fatal(err)
	}
	// Deliberately omit client cancellation: a disconnected old worker must not
	// leave its expensive statement and advisory lock alive on the server.
	started := time.Now()
	_, err = tx.ExecContext(context.Background(), `SELECT pg_sleep(1)`)
	if err == nil || !strings.Contains(err.Error(), "statement timeout") || time.Since(started) > 800*time.Millisecond {
		t.Fatalf("server did not enforce transaction statement budget: elapsed=%s err=%v", time.Since(started), err)
	}
	if got := nextIdentityBatchSize(100, err, 0); got != 50 {
		t.Fatalf("server timeout must shrink retry batch: got %d", got)
	}
}
