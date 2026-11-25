package discovery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHardwareTrendUsesScopedRecordsAndPreservesMissingHistory(t *testing.T) {
	db := discoveryTestSchema(t)
	at := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	if _, err := db.Exec(`CREATE TABLE passive_hardware_current (sensor_id text,identity_key text,first_seen timestamptz,last_seen timestamptz);
		CREATE TABLE passive_hardware_changes (identity_key text,changed_at timestamptz,before_status text,after_status text,before_type text,after_type text);
		CREATE TABLE passive_hardware_runtime(sensor_id text,available_from timestamptz,backfill_started_at timestamptz,last_success_at timestamptz);
		INSERT INTO passive_hardware_current VALUES ('site','a','2026-11-24Z','2026-11-25Z'), ('site','b','2026-10-10Z','2026-11-18Z'),('site','c','2026-10-10Z','2026-11-11Z'),
		('other','d','2026-11-24Z','2026-11-25Z');
		INSERT INTO passive_hardware_changes VALUES('a','2026-11-24Z','identified','identified','printer','camera'),('a','2026-11-25Z','identified','identified','camera','printer'),
		('b','2026-11-24Z','candidate','identified','','camera'),('d','2026-11-24Z','identified','identified','printer','camera');`); err != nil {
		t.Fatal(err)
	}
	result, err := hardwareTrend(context.Background(), db, "site", at, 7*24*time.Hour)
	if err != nil || result.FirstSeen != 1 || result.ChangedType != 1 || result.PreviousOnly != 1 || result.WindowDays != 7 {
		t.Fatalf("trend=%+v err=%v", result, err)
	}
	empty, err := hardwareTrend(context.Background(), db, "empty", at, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(empty)
	if err != nil || strings.Contains(string(raw), "first_seen") || strings.Contains(string(raw), "changed_type") || strings.Contains(string(raw), "previous_only") {
		t.Fatalf("missing history reported counts: %s %v", raw, err)
	}
}
