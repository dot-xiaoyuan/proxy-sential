package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestIngestSourceLeasesLeaveQueryConnections(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_acceptance_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires owned isolated database")
	}
	store, err := NewPostgresStore(PostgresOptions{DSN: dsn, SensorID: fmt.Sprintf("ingest-lease-test-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var releases []func()
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for i := 0; i < 3; i++ {
		release, err := store.AcquireIngestSourceLease(ctx, "suricata", fmt.Sprintf("/test/source-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	var value int
	if err := store.db.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != 1 {
		t.Fatalf("query result = %d, want 1", value)
	}
}
