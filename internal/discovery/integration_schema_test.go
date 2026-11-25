package discovery

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Each connection uses the private schema. Failed setup and worker reconnects
// cannot leave a later replay reading another test's devices or queue.
func discoveryTestSchema(t *testing.T) *sql.DB {
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
	schema := fmt.Sprintf("discovery_replay_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	return db
}

func applyDiscoveryTestSQL(t *testing.T, db *sql.DB, migrations ...string) {
	t.Helper()
	for _, file := range migrations {
		raw, err := os.ReadFile("../../migrations/postgres/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(raw)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
}

func legacyDiscoveryReplayDB(t *testing.T) *sql.DB {
	t.Helper()
	db := discoveryTestSchema(t)
	if _, err := db.Exec("CREATE TABLE endpoint_entities(endpoint_id text PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	applyDiscoveryTestSQL(t, db, "058_network_discovery.sql", "083_discovery_latest.sql")
	return db
}

func deferredRecognitionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := discoveryTestSchema(t)
	if _, err := db.Exec(`CREATE TABLE endpoint_entities (LIKE public.endpoint_entities INCLUDING ALL);
		CREATE TABLE endpoint_recognition_jobs (LIKE public.endpoint_recognition_jobs INCLUDING ALL)`); err != nil {
		t.Fatal(err)
	}
	applyDiscoveryTestSQL(t, db, "232_job_enqueue_outbox.sql")
	return db
}

func discoveryAcceptancePG(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_READY_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL test instance required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback.Host != cfg.Host {
			t.Fatal("test DSN must not contain fallback hosts")
		}
	}
	if !filepath.IsAbs(cfg.Host) {
		addresses, err := net.LookupIP(cfg.Host)
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			if address.Equal(net.ParseIP("222.204.3.184")) || address.Equal(net.ParseIP("222.204.3.204")) || address.Equal(net.ParseIP("192.168.0.30")) {
				t.Fatal("test DSN resolves to a field host")
			}
		}
	}
	return cfg
}
