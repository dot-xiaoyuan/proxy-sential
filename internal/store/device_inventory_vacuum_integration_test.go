package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestDeviceInventoryVacuumMaintenanceMigration(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires owned isolated database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if _, err = ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	check := func(t *testing.T) {
		t.Helper()
		for _, toast := range []bool{false, true} {
			for key, want := range map[string]string{"autovacuum_vacuum_scale_factor": "0.02", "autovacuum_vacuum_threshold": "2000"} {
				var value string
				err = db.QueryRowContext(ctx, `SELECT o.option_value FROM pg_class c CROSS JOIN LATERAL pg_options_to_table(c.reloptions) o WHERE c.oid=CASE WHEN $1 THEN (SELECT reltoastrelid FROM pg_class WHERE oid='public.device_inventory_snapshots'::regclass) ELSE 'public.device_inventory_snapshots'::regclass END AND o.option_name=$2`, toast, key).Scan(&value)
				if err != nil || value != want {
					t.Errorf("toast=%v option=%s value=%s want=%s err=%v", toast, key, value, want, err)
				}
			}
		}
	}
	t.Run("heap_and_toast_maintenance", func(t *testing.T) { check(t) })
	t.Run("idempotent", func(t *testing.T) {
		result, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres")
		if err != nil || len(result.Applied) != 0 {
			t.Fatal(result, err)
		}
		check(t)
	})
	t.Run("lock_timeout_is_atomic_and_retryable", func(t *testing.T) {
		const name = "076_device_inventory_vacuum_maintenance.sql"
		if _, err = db.ExecContext(ctx, `ALTER TABLE device_inventory_snapshots RESET (autovacuum_vacuum_scale_factor,autovacuum_vacuum_threshold,toast.autovacuum_vacuum_scale_factor,toast.autovacuum_vacuum_threshold)`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version=$1`, name); err != nil {
			t.Fatal(err)
		}
		lock, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback()
		if _, err = lock.ExecContext(ctx, `LOCK TABLE device_inventory_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres")
		if err == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("migration did not stop at bounded lock deadline: err=%v elapsed=%v", err, time.Since(start))
		}
		var count int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=$1`, name).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed migration was ledgered", count, err)
		}
		if err = lock.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Fatal(err)
		}
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_class c CROSS JOIN LATERAL pg_options_to_table(c.reloptions) o WHERE c.oid IN ('public.device_inventory_snapshots'::regclass,(SELECT reltoastrelid FROM pg_class WHERE oid='public.device_inventory_snapshots'::regclass)) AND o.option_name IN ('autovacuum_vacuum_scale_factor','autovacuum_vacuum_threshold')`).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial maintenance settings escaped rollback", count, err)
		}
		result, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres")
		if err != nil || len(result.Applied) != 1 || result.Applied[0] != name {
			t.Fatal(result, err)
		}
		check(t)
	})
}
