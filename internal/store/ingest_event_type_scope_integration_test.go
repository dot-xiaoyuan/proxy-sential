package store

import (
	"context"
	"net/url"
	"os"
	"proxy-sentinel/internal/ingest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestClickHouseIngestTypesRespectSensorAndClosedTimeWindow(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("owned isolated ClickHouse required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^sentinel_acceptance_[0-9]+$`).MatchString(u.Query().Get("database")) {
		t.Fatal("requires owned isolated ClickHouse database")
	}
	s, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn, RequestTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = s.exec(ctx, `CREATE TABLE normalized_events(sensor_id String,type String,timestamp DateTime64(9,'UTC')) ENGINE=MergeTree ORDER BY(sensor_id,timestamp)`); err != nil {
		t.Fatal(err)
	}
	a := "collector'a"
	b := "other"
	sql := `INSERT INTO normalized_events VALUES (` + chQuote(a) + `,'dns',now64(9)-INTERVAL 1 MILLISECOND),(` + chQuote(b) + `,'http',now()-INTERVAL 1 HOUR),(` + chQuote(b) + `,'http',now()-INTERVAL 2 HOUR),(` + chQuote(a) + `,'future',now()+INTERVAL 1 HOUR),(` + chQuote(a) + `,'expired',now()-INTERVAL 25 HOUR)`
	if err = s.exec(ctx, sql); err != nil {
		t.Fatal(err)
	}
	global, err := s.ListIngestEventTypes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, v := range global {
		total += v.Count
	}
	if total != 3 {
		t.Fatalf("future/expired event counted as current: %+v", global)
	}
	reader, ok := any(s).(interface {
		ListSensorIngestEventTypes(context.Context, string) ([]ingest.EventTypeCount, error)
	})
	if !ok {
		t.Fatal("sensor-scoped event type reader unavailable")
	}
	for _, tc := range []struct {
		sensor string
		count  int
	}{{a, 1}, {b, 2}, {"quiet", 0}} {
		items, err := reader.ListSensorIngestEventTypes(ctx, tc.sensor)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, v := range items {
			count += v.Count
			if v.Type == "future" || v.Type == "expired" {
				t.Fatal("time scope ignored")
			}
		}
		if count != tc.count {
			t.Fatalf("sensor count borrowed: sensor=%q count=%d want=%d", tc.sensor, count, tc.count)
		}
	}
	rows, err := s.query(ctx, `SELECT count() AS count FROM normalized_events FORMAT JSONEachRow`)
	if err != nil || !strings.Contains(string(rows), `"count":5`) {
		t.Fatal("raw events changed", string(rows), err)
	}
}
