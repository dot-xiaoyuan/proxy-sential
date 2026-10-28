package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Only a dedicated remote test instance may run this synthetic transaction
// replay. The user's disabled local stack and the 184 field host are excluded.
func TestStreamArchiveOverlappingConfirmationsUseStableLockOrder(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_READY_DSN")
	if dsn == "" {
		t.Skip("dedicated remote PostgreSQL test instance required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.ToLower(cfg.Host)
	ip := net.ParseIP(host)
	if host == "" || host == "localhost" || host == "222.204.3.184" || (ip != nil && ip.IsLoopback()) || strings.HasPrefix(host, "/") {
		t.Fatal("archive lock replay cannot run locally or on 184")
	}
	resolved, err := net.LookupIP(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range resolved {
		if address.IsLoopback() || address.Equal(net.ParseIP("222.204.3.184")) {
			t.Fatal("archive lock replay resolves locally or to 184")
		}
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback.Host != cfg.Host {
			t.Fatal("archive lock replay DSN must not contain fallback hosts")
		}
	}
	admin := stdlib.OpenDB(*cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	schema := fmt.Sprintf("archive_lock_test_%d", time.Now().UnixNano())
	if _, err = admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	isolated := cfg.Copy()
	if isolated.RuntimeParams == nil {
		isolated.RuntimeParams = map[string]string{}
	}
	isolated.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*isolated)
	defer func() {
		db.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		admin.Close()
	}()
	_, err = db.ExecContext(ctx, `CREATE TABLE stream_discovery_event_keys(epoch text,scope_id text,event_key text,content_sha256 text,accepted_month date,PRIMARY KEY(epoch,scope_id,event_key));
 CREATE TABLE stream_discovery_receipts(accepted_month date,epoch text,scope_id text,event_key text,content_sha256 text,archive_state text,archive_confirmed_at timestamptz,PRIMARY KEY(accepted_month,epoch,scope_id,event_key));
 INSERT INTO stream_discovery_event_keys VALUES('fresh','scope','a','hash-a','2026-10-01'),('fresh','scope','b','hash-b','2026-10-01');
 INSERT INTO stream_discovery_receipts VALUES('2026-10-01','fresh','scope','a','hash-a','pending',NULL),('2026-10-01','fresh','scope','b','hash-b','pending',NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `SELECT 1 FROM stream_discovery_receipts WHERE epoch='fresh' AND scope_id='scope' AND event_key='a' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	// Both requests contain the same stable ordinals but opposite JSON order.
	// Holding the first receipt forces overlap before either can finish.
	inputs := []string{
		`[{"ordinal":0,"scope_id":"scope","event_key":"a","content_sha256":"hash-a"},{"ordinal":1,"scope_id":"scope","event_key":"b","content_sha256":"hash-b"}]`,
		`[{"ordinal":1,"scope_id":"scope","event_key":"b","content_sha256":"hash-b"},{"ordinal":0,"scope_id":"scope","event_key":"a","content_sha256":"hash-a"}]`,
	}
	type result struct {
		count int
		err   error
	}
	results := make(chan result, 2)
	started := make(chan int32, 2)
	for _, input := range inputs {
		go func(input string) {
			conn, err := db.Conn(ctx)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer conn.Close()
			var pid int32
			if err = conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				results <- result{err: err}
				return
			}
			started <- pid
			var n int
			err = conn.QueryRowContext(ctx, confirmStreamArchiveReceiptsSQL, "fresh", input).Scan(&n)
			results <- result{n, err}
		}(input)
	}
	pids := make([]int32, 0, 2)
	for len(pids) < 2 {
		select {
		case pid := <-started:
			pids = append(pids, pid)
		case got := <-results:
			t.Fatalf("confirmation failed before lock check: %+v", got)
		case <-ctx.Done():
			t.Fatal("confirmation connections did not start")
		}
	}
	waitLimit := time.NewTimer(3 * time.Second)
	defer waitLimit.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1::integer[]) AND wait_event_type='Lock'`, pids).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 2 {
			break
		}
		select {
		case got := <-results:
			t.Fatalf("confirmation bypassed held receipt lock: %+v", got)
		case <-waitLimit.C:
			t.Fatalf("both confirmations did not wait on a lock; observed %d", waiting)
		case <-ctx.Done():
			t.Fatal("timeout while checking lock waits")
		case <-ticker.C:
		}
	}
	if err = blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	for range inputs {
		select {
		case got := <-results:
			if got.err != nil || got.count != 2 {
				t.Fatalf("overlapping confirmation failed: %+v", got)
			}
		case <-ctx.Done():
			t.Fatal("overlapping confirmations did not complete")
		}
	}
}
