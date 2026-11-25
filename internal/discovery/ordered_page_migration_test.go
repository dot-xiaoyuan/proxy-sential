package discovery

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestOrderedPageConcurrentPrebuild(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_DISCOVERY_PAGE_GROWTH") != "1" {
		t.Skip("opt-in local migration replay")
	}
	cfg, err := pgx.ParseConfig(os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil || !strings.HasPrefix(cfg.Host, "/") {
		t.Fatal("local socket required", err)
	}
	db := hardwareIntegrationDB(t)
	applyDiscoveryTestSQL(t, db, "252_discovery_list_projection.sql", "253_discovery_queue_generations.sql", "254_discovery_address_links_and_reports.sql")
	migration, err := os.ReadFile("../../migrations/postgres/256_discovery_page_indexes.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO discovery_observation_latest(id,origin,withdrawn,data) VALUES('keep','arp',false,'{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(migration)); err == nil || !strings.Contains(err.Error(), "prebuild") {
		t.Fatalf("live table accepted without concurrent build: %v", err)
	}
	prebuild, err := exec.Command("python3", "../../scripts/deploy/prebuild-discovery-page-indexes.py").Output()
	if err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := db.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	run := func() error {
		c := exec.Command("psql", "-X", "-q", "-h", cfg.Host, "-p", fmt.Sprint(cfg.Port), "-U", cfg.User, "-d", cfg.Database)
		c.Env = append(os.Environ(), "PGOPTIONS=-c search_path="+schema)
		c.Stdin = bytes.NewReader(prebuild)
		buf, err := c.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, buf)
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		if err := run(); err != nil {
			t.Fatal(err)
		}
	}
	var absent bool
	if err := db.QueryRow("SELECT to_regprocedure('discovery_list_page_sources(text[])') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatal("prebuild executed migration outside runner", err)
	}
	// A same-name index with different keys must block the ordinary migration.
	if _, err := db.Exec("DROP INDEX discovery_page_mac; CREATE INDEX discovery_page_mac ON discovery_list_observation(raw_mac)"); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "mismatched") {
		t.Fatalf("prebuild accepted wrong keys: %v", err)
	}
	if _, err := db.Exec(string(migration)); err == nil || !strings.Contains(err.Error(), "mismatched") {
		t.Fatalf("migration accepted wrong keys: %v", err)
	}
	if _, err := db.Exec("DROP INDEX discovery_page_mac"); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
}
