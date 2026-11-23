package store

import (
	"context"
	"os"
	"testing"
)

func newActivityIntegrationStore(t *testing.T) *DBStore {
	t.Helper()
	pg := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	ch := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if pg == "" || ch == "" {
		t.Skip("activity integration requires dedicated PostgreSQL and ClickHouse test DSNs")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, pg, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyClickHouseMigrations(ctx, ch, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	s, err := NewDBStore(Options{PostgresDSN: pg, ClickHouseDSN: ch})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
