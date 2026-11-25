package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Projection replays exercise triggers, dispatchers and tables in public.
// A private migrated database isolates their work even when a test fails.
func privateMigratedTestPostgres(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { admin.Close() })
	name := fmt.Sprintf("sentinel_acceptance_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE " + name); err != nil {
			t.Error(err)
		}
	})
	cfg.Database = name
	privateDSN := stdlib.RegisterConnConfig(cfg)
	t.Cleanup(func() { stdlib.UnregisterConnConfig(privateDSN) })
	if _, err := ApplyPostgresMigrations(context.Background(), privateDSN, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: privateDSN})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	return pg
}
