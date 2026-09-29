package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func appIntegrationDB(t *testing.T) *applicationDB {
	t.Helper()
	pg := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	ch := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if pg == "" || ch == "" {
		t.Skip("application integration requires dedicated PostgreSQL and ClickHouse test DSNs")
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
	t.Cleanup(func() { s.pg.Close() })
	return &applicationDB{store: s, syncConnectionReadModel: true}
}
func TestApplicationDatabaseAccountingReplay(t *testing.T) {
	d := appIntegrationDB(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../appdomain/testdata/accounting.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []appdomain.Observation
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	// Relative times avoid requiring a fixed test clock or bypassing retention.
	base := time.Now().UTC().Truncate(time.Second).Add(-3 * time.Hour)
	fixture := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	sensor := fmt.Sprintf("app-replay-%d", time.Now().UnixNano())
	for i := range rows {
		tm, _ := time.Parse(time.RFC3339Nano, rows[i].Timestamp)
		rows[i].Timestamp = base.Add(tm.Sub(fixture)).Format(time.RFC3339Nano)
		rows[i].SensorID = sensor + rows[i].SensorID
	}
	t.Cleanup(func() {
		cleanupApplicationTestData(ctx, d.store, sensor, true)
	})
	if err = d.write(ctx, rows, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err = d.write(ctx, rows, 0, 1); err != nil {
		t.Fatal(err)
	} // duplicates before background merge
	for _, filter := range []appdomain.Query{
		{From: base.Add(-time.Hour), To: base.Add(time.Hour)},
		{From: base.Add(-time.Hour), To: base.Add(time.Hour), CampusID: "a"},
		{From: base.Add(-time.Hour), To: base.Add(time.Hour), CampusID: "a", ApplicationID: "qq"},
		{From: base.Add(-time.Hour), To: base.Add(time.Hour), IP: "10.0.0.1"},
	} {
		// Use one sensor for strict isolation from other tests.
		filter.SensorID = sensor + "s"
		expected := appdomain.Aggregate(rows, filter)
		got, e := d.Report(ctx, filter)
		if e != nil {
			t.Fatal(e)
		}
		if asOf, parseErr := time.Parse(time.RFC3339Nano, got.AsOf); parseErr != nil || time.Since(asOf) > 5*time.Second {
			t.Fatalf("invalid statistics timestamp: %q", got.AsOf)
		}
		got.AsOf = ""
		if !reflect.DeepEqual(expected, got) {
			a, _ := json.Marshal(expected)
			b, _ := json.Marshal(got)
			t.Fatalf("accounting mismatch\nwant %s\ngot  %s", a, b)
		}
		page, e := d.Page(ctx, filter, appdomain.PageRequest{Limit: 2})
		if e != nil {
			t.Fatal(e)
		}
		seen := map[string]bool{}
		for {
			for _, o := range page.Items {
				if seen[o.Key()] {
					t.Fatal("duplicate on cursor pages")
				}
				seen[o.Key()] = true
			}
			if page.NextCursor == "" {
				break
			}
			page, e = d.Page(ctx, filter, appdomain.PageRequest{Limit: 2, Cursor: page.NextCursor})
			if e != nil {
				t.Fatal(e)
			}
		}
		var out bytes.Buffer
		if e = d.Export(ctx, filter, &out); e != nil {
			t.Fatal(e)
		}
		var want bytes.Buffer
		enc := json.NewEncoder(&want)
		for _, u := range appdomain.UnknownDomains(rows, filter) {
			_ = enc.Encode(u)
		}
		if out.String() != want.String() {
			t.Fatalf("unknown mismatch: %s / %s", out.String(), want.String())
		}
	}
	// A newer classification replaces the complete result; ordinary scans cannot
	// replace it even when their batch ID is newer.
	changed := rows[0]
	changed.Match = appdomain.Match{TargetID: "new", TargetType: "application", Name: "new"}
	changed.BundleVersion = "v2"
	if err = d.write(ctx, []appdomain.Observation{changed}, 2, 4); err != nil {
		t.Fatal(err)
	}
	if err = d.write(ctx, rows[:1], 0, 10); err != nil {
		t.Fatal(err)
	}
	if err = d.write(ctx, rows[:1], 1, 11); err != nil {
		t.Fatal(err)
	}
	q := appdomain.Query{From: base.Add(-3 * time.Hour), To: base.Add(time.Hour), SensorID: changed.SensorID}
	page, err := d.Page(ctx, q, appdomain.PageRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range page.Items {
		if o.EventID == changed.EventID && o.BundleVersion != "v2" {
			t.Fatal("stale write overrode classification")
		}
	} // Aggregate counts must remove the obsolete classification as well, not
	// just return the new JSON in the detail page.
	revised := append([]appdomain.Observation(nil), rows...)
	revised[0] = changed
	expected := appdomain.Aggregate(revised, q)
	got, err := d.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	got.AsOf = ""
	if !reflect.DeepEqual(expected, got) {
		a, _ := json.Marshal(expected)
		b, _ := json.Marshal(got)
		t.Fatalf("reclassification summary mismatch expected=%s got=%s", a, b)
	}
	if page.Total != expected.ObservationCount {
		t.Fatalf("total=%d observations=%d", page.Total, expected.ObservationCount)
	}

}

// Five-minute summaries must remain identical to the exact reference when a
// connection crosses buckets, changes IP, or has observations beyond query To.
func TestApplicationConnectionBucketBoundaryReplay(t *testing.T) {
	d := appIntegrationDB(t)
	ctx := context.Background()
	sensor := fmt.Sprintf("bucket-replay-%d", time.Now().UnixNano())
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(5 * time.Minute)
	raw, err := os.ReadFile("../appdomain/testdata/accounting.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []appdomain.Observation
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		rows[i].SensorID = sensor + rows[i].SensorID
		switch rows[i].EventID {
		case "early":
			rows[i].Timestamp = base.Add(-time.Minute).Format(time.RFC3339Nano)
		case "future":
			rows[i].Timestamp = base.Add(11 * time.Minute).Format(time.RFC3339Nano)
			rows[i].IP = "10.0.0.2"
		default:
			rows[i].Timestamp = base.Add(time.Minute).Format(time.RFC3339Nano)
		}
	}
	t.Cleanup(func() { cleanupApplicationTestData(ctx, d.store, sensor, true) })
	// Reversed arrival and duplicate ingestion must not affect the summary.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	if err = d.write(ctx, rows, 1, 4); err != nil {
		t.Fatal(err)
	}
	if err = d.write(ctx, rows, 1, 4); err != nil {
		t.Fatal(err)
	}
	compare := func(q appdomain.Query) {
		t.Helper()
		expected := appdomain.Aggregate(rows, q)
		actual, err := d.Report(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		actual.AsOf = ""
		if !reflect.DeepEqual(expected, actual) {
			a, _ := json.Marshal(expected)
			b, _ := json.Marshal(actual)
			t.Fatalf("bucket accounting mismatch for %+v\nwant %s\ngot %s", q, a, b)
		}
	}
	for _, bounds := range [][2]time.Duration{{-2 * time.Minute, 15 * time.Minute}, {0, 5 * time.Minute}, {30 * time.Second, 90 * time.Second}, {0, 12 * time.Minute}, {5 * time.Minute, 12 * time.Minute}, {-24 * time.Hour, 24 * time.Hour}, {-7 * 24 * time.Hour, 24 * time.Hour}} {
		for _, ip := range []string{"", "10.0.0.1", "10.0.0.2"} {
			for _, campus := range []string{"", "a", "b", "missing"} {
				compare(appdomain.Query{From: base.Add(bounds[0]), To: base.Add(bounds[1]), SensorID: sensor + "s", CampusID: campus, IP: ip})
			}
		}
	}
	for i := range rows {
		if rows[i].EventID == "early" {
			rows[i].Match = appdomain.Match{TargetID: "replacement", TargetType: "application", Name: "replacement", Category: "test"}
			rows[i].BundleVersion = "v2"
			if err = d.write(ctx, rows[i:i+1], 2, 5); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	compare(appdomain.Query{From: base.Add(-2 * time.Minute), To: base.Add(15 * time.Minute), SensorID: sensor + "s"})
}

func cleanupApplicationTestData(ctx context.Context, s *DBStore, sensor string, prefix bool) {
	where := "sensor_id=" + chQuote(sensor)
	if prefix {
		where = "startsWith(sensor_id," + chQuote(sensor) + ")"
	}
	for _, table := range []string{"application_observations", "application_latest_observations", "application_connection_observations", "application_connection_observations_v2", "application_connection_dirty_log", "application_connection_summaries", "application_connection_summaries_v2", "application_connection_bucket_facts", "application_observation_bucket_facts", "application_observation_bucket_facts_v2", "application_observation_hour_facts", "application_observation_day_facts", "application_observation_dirty_log"} {
		_ = s.ch.exec(ctx, "ALTER TABLE "+table+" DELETE WHERE "+where+" SETTINGS mutations_sync=2")
	}
}
