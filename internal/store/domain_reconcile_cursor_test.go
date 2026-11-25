package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func TestDomainReconcileResumesAcrossEmptyHistorySlices(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" || os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN") == "" {
		t.Skip("isolated PostgreSQL and ClickHouse required")
	}
	t.Setenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN", privateClickHouseTestDatabase(t, dsn))
	s := newActivityIntegrationStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	sensor := fmt.Sprintf("reconcile-sparse-%d", now.UnixNano())
	s.pg.sensorID = sensor
	library := fingerprint.Default()
	start := now.Add(-3 * time.Hour)
	t.Cleanup(func() {
		if _, err := s.pg.db.ExecContext(ctx, "DELETE FROM domain_reconcile_cursors WHERE sensor_id=$1", sensor); err != nil {
			t.Error(err)
		}
	})
	if _, err := s.pg.db.ExecContext(ctx, `INSERT INTO domain_reconcile_cursors(sensor_id,rule_version,kind,cursor_timestamp) VALUES($1,$2,'daily',$3)`, sensor, library.Version(), start); err != nil {
		t.Fatal(err)
	}
	event := brandReplay(t)[0]
	event.Observer["sensor_id"] = sensor
	event.EventID, event.Timestamp = sensor, now.Add(-time.Minute).Format(time.RFC3339Nano)
	if err := s.ch.WriteNormalizedEvents(ctx, []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	position := func() (time.Time, bool) {
		t.Helper()
		var at time.Time
		var done bool
		if err := s.pg.db.QueryRowContext(ctx, `SELECT cursor_timestamp,completed_at IS NOT NULL FROM domain_reconcile_cursors WHERE sensor_id=$1 AND kind='daily'`, sensor).Scan(&at, &done); err != nil {
			t.Fatal(err)
		}
		return at, done
	}
	if err := s.reconcileDomainCursor(ctx, library, "daily"); err != nil {
		t.Fatal(err)
	}
	if at, done := position(); done || !at.Equal(start.Add(2*time.Hour)) {
		t.Fatalf("bounded pass across empty slices: cursor=%s done=%v", at, done)
	}
	if err := s.reconcileDomainCursor(ctx, library, "daily"); err != nil {
		t.Fatal(err)
	}
	if at, done := position(); !done || at.Before(now) {
		t.Fatalf("remaining history not covered: cursor=%s done=%v", at, done)
	}
	raw, err := s.ch.query(ctx, `SELECT count() count FROM domain_ecosystem_observations FINAL WHERE sensor_id=`+chQuote(sensor)+` FORMAT JSONEachRow`)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := decodeSingleCount(raw); err != nil || count != 1 {
		t.Fatalf("evidence beyond empty slices: count=%d err=%v", count, err)
	}
}

// Starting a ten-minute overlap must never lower an already confirmed
// watermark. Empty time slices can advance it once their reads finish.
func TestDomainReconcileOverlapNeverRewindsConfirmedWatermark(t *testing.T) {
	now := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	since := now.Add(-7 * 24 * time.Hour)
	stored, storedID := now.Add(-time.Hour), "evt-9"
	for pass := 0; pass < 50; pass++ {
		read, readID := domainReconcileStart("incremental", true, stored, storedID, since)
		if !read.Equal(stored.Add(-10 * time.Minute)) {
			t.Fatalf("pass %d read start %s, want ten-minute overlap", pass, read)
		}
		stored, storedID = domainReconcileHighWater(read, readID, stored, storedID)
	}
	if !stored.Equal(now.Add(-time.Hour)) || storedID != "evt-9" {
		t.Fatalf("empty passes moved the cursor to %s/%s", stored, storedID)
	}
}

func TestDomainReconcileHighWaterAdvancesWithProgress(t *testing.T) {
	high := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	if at, id := domainReconcileHighWater(high.Add(time.Second), "a", high, "z"); !at.Equal(high.Add(time.Second)) || id != "a" {
		t.Fatalf("progress not kept: %s %s", at, id)
	}
	if at, id := domainReconcileHighWater(high, "b", high, "a"); !at.Equal(high) || id != "b" {
		t.Fatalf("same-timestamp progress not kept: %s %s", at, id)
	}
	floor := high.Add(-time.Hour)
	if at, id := domainReconcileStart("daily", true, high, "x", floor); !at.Equal(floor) || id != "" {
		t.Fatalf("daily restart wrong: %s %s", at, id)
	}
}
