package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

func TestCollectorRunQueryPostgresPreservesGlobalOrdering(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for _, q := range []string{
		`CREATE TEMP TABLE sensors(sensor_id text PRIMARY KEY)`,
		`CREATE TEMP TABLE collector_runs(run_id text PRIMARY KEY,sensor_id text REFERENCES sensors(sensor_id),started_at timestamptz,finished_at timestamptz,previous_offset bigint DEFAULT 0,new_offset bigint DEFAULT 0,truncated bool DEFAULT false,normalized_read bigint DEFAULT 0,normalized_emitted bigint DEFAULT 0,normalized_skipped bigint DEFAULT 0,normalized_malformed bigint DEFAULT 0,evidence_count bigint DEFAULT 0,risk_count bigint DEFAULT 0,risk_list_count bigint DEFAULT 0,summary jsonb DEFAULT '{}')`,
		`CREATE INDEX ON collector_runs(sensor_id,started_at DESC)`,
		`INSERT INTO sensors VALUES ('a'),('b'),('c'),('quiet')`,
	} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	s := &PostgresStore{db: db}
	if r, e := s.ListRuns(ctx, 1); e != nil || len(r) != 0 {
		t.Fatal("empty history", r, e)
	}
	type expected struct {
		id, sensor string
		at         time.Time
		n          int
	}
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	items := []expected{}
	for _, sensor := range []string{"c", "a", "b"} {
		for i := 0; i < 80; i++ {
			id := fmt.Sprintf("%s-%03d", sensor, i)
			at := base.Add(time.Duration(i/3) * time.Second)
			items = append(items, expected{id, sensor, at, i})
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO collector_runs(run_id,sensor_id,started_at,finished_at,normalized_read,summary)
 SELECT sensor||'-'||lpad(i::text,3,'0'),sensor,$1::timestamptz+(i/3)*interval '1 second',$1::timestamptz+(i/3+1)*interval '1 second',i,'{"normalized":{"by_type":{"http":7}},"zeek_status":"ready"}'::jsonb
 FROM (VALUES ('c'),('a'),('b')) sensors(sensor) CROSS JOIN generate_series(0,79) i`, base); err != nil {
		t.Fatal(err)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].at.Equal(items[j].at) {
			return items[i].id > items[j].id
		}
		return items[i].at.After(items[j].at)
	})
	for _, limit := range []int{1, 5, 50, 100, 300, 0} {
		got, e := s.ListRuns(ctx, limit)
		if e != nil {
			t.Fatal(e)
		}
		size := limit
		if size == 0 {
			size = 50
		}
		size = min(size, len(items))
		if len(got) != size {
			t.Fatalf("limit %d: %d rows", limit, len(got))
		}
		for i, r := range got {
			w := items[i]
			if r.RunID != w.id || r.SensorID != w.sensor || !sameCollectorInstant(r.StartedAt, w.at) || r.Normalized.Read != w.n || r.Normalized.ByType["http"] != 7 || r.ZeekStatus != "ready" {
				t.Fatalf("limit %d index %d lost ordering or summary: %+v want %+v", limit, i, r, w)
			}
		}
	}
	// A disconnected/failed database is still a real error, not empty history.
	for _, term := range []string{"", "c-"} {
		filtered := []expected{}
		for _, item := range items {
			if term == "" || item.sensor == "c" {
				filtered = append(filtered, item)
			}
		}
		for _, offset := range []int{0, 4, 40, 241} {
			got, page, err := s.ListRunsPage(ctx, Query{Limit: 20, Cursor: offset, Q: term})
			if err != nil || page.Total != len(filtered) || len(got) != max(0, min(20, len(filtered)-offset)) {
				t.Fatalf("global page term=%q offset=%d got=%d total=%d error=%v", term, offset, len(got), page.Total, err)
			}
			for i, row := range got {
				if row.RunID != filtered[offset+i].id {
					t.Fatalf("page lost sensor/tie ordering: %+v", row)
				}
			}
		}
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, e := s.ListRuns(cancelled, 1); e == nil {
		t.Fatal("cancelled read reported empty success")
	}
}

func sameCollectorInstant(value string, want time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Equal(want)
}
