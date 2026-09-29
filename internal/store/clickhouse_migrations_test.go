package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSplitClickHouseMigrationPreservesQuotedSemicolon(t *testing.T) {
	items, err := splitClickHouseMigration("CREATE TABLE a(x String) ENGINE=Memory; INSERT INTO a VALUES ('a;b');")
	if err != nil || len(items) != 2 || items[1] != "INSERT INTO a VALUES ('a;b')" {
		t.Fatalf("unexpected statements: %#v err=%v", items, err)
	}
}

func TestSplitClickHouseMigrationIgnoresCommentSemicolon(t *testing.T) {
	items, err := splitClickHouseMigration("-- rollout note; no backfill\nCREATE TABLE a(x String) ENGINE=Memory;")
	if err != nil || len(items) != 1 || items[0] != "CREATE TABLE a(x String) ENGINE=Memory" {
		t.Fatalf("unexpected statements: %#v err=%v", items, err)
	}
}

func TestApplyClickHouseMigrationsTracksChecksums(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN is not set")
	}
	dir := t.TempDir()
	name := fmt.Sprintf("900_t8_%d.sql", time.Now().UnixNano())
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("CREATE TABLE IF NOT EXISTS t8_migration_probe(value String) ENGINE=Memory;"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	clickhouse, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = clickhouse.exec(cleanup, "ALTER TABLE schema_migrations DELETE WHERE version="+chQuote(name)+" SETTINGS mutations_sync=2")
	})
	first, err := ApplyClickHouseMigrations(ctx, dsn, dir)
	if err != nil || len(first.Applied) != 1 {
		t.Fatalf("first migration failed: %+v err=%v", first, err)
	}
	second, err := ApplyClickHouseMigrations(ctx, dsn, dir)
	if err != nil || len(second.Applied) != 0 || second.Current != name {
		t.Fatalf("migration was not idempotent: %+v err=%v", second, err)
	}
	if err := os.WriteFile(path, []byte("CREATE TABLE IF NOT EXISTS t8_migration_probe(value UInt64) ENGINE=Memory;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyClickHouseMigrations(ctx, dsn, dir); err == nil {
		t.Fatal("changed migration checksum must be rejected")
	}
}
