package store

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestIngestStatusDoesNotBorrowOtherSensorRun(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires owned isolated database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, q := range []string{
		`CREATE TEMP TABLE sensors(sensor_id text PRIMARY KEY)`,
		`CREATE TEMP TABLE collector_runs(run_id text PRIMARY KEY,sensor_id text REFERENCES sensors(sensor_id),started_at timestamptz,finished_at timestamptz,previous_offset bigint DEFAULT 0,new_offset bigint DEFAULT 0,truncated bool DEFAULT false,normalized_read bigint DEFAULT 0,normalized_emitted bigint DEFAULT 0,normalized_skipped bigint DEFAULT 0,normalized_malformed bigint DEFAULT 0,evidence_count bigint DEFAULT 0,risk_count bigint DEFAULT 0,risk_list_count bigint DEFAULT 0,summary jsonb DEFAULT '{}')`,
		`CREATE INDEX ON collector_runs(sensor_id,started_at DESC)`,
		`INSERT INTO sensors VALUES('local'),('other'),('quiet')`,
		`INSERT INTO collector_runs(run_id,sensor_id,started_at,finished_at,normalized_read,normalized_malformed,summary) VALUES('local-run','local',now()-interval '1 hour',now()-interval '1 hour',3,1,'{"normalized":{"by_type":{"dns":3}},"zeek_status":"ready"}'),('other-run','other',now(),now(),99,0,'{}')`,
	} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{\"type\":\"dns\",\"count\":2}\n")) }))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	pg := &PostgresStore{db: db, sensorID: "local"}
	s := &DBStore{pg: pg, ch: ch}
	status, err := s.IngestStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.LatestRunID != "local-run" || status.LastCounters["read"] != 3 || status.Healthy || status.Severity != "warning" {
		t.Fatalf("other collector replaced local status: %+v", status)
	}
	pg.sensorID = "quiet"
	status, err = s.IngestStatus(ctx)
	if err != nil || status.LatestRunID != "" || status.Healthy {
		t.Fatalf("quiet sensor borrowed activity: %+v %v", status, err)
	}
	rows, err := pg.ListRuns(ctx, 1)
	if err != nil || len(rows) != 1 || rows[0].RunID != "other-run" {
		t.Fatalf("global history changed: %+v %v", rows, err)
	}
}
