package store

import (
	"strings"
	"testing"
	"time"
)

func TestApplicationLegacyBackfillIsOptIn(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED", "")
	t.Setenv("PROXY_SENTINEL_RUN_LEGACY_BACKFILL", "")
	if applicationLegacyBackfillRequired() {
		t.Fatal("legacy application backfill must be disabled by default")
	}

	t.Setenv("PROXY_SENTINEL_RUN_LEGACY_BACKFILL", "true")
	if !applicationLegacyBackfillRequired() {
		t.Fatal("explicit legacy backfill opt-in was ignored")
	}

	t.Setenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED", "true")
	if applicationLegacyBackfillRequired() {
		t.Fatal("explicit history disable must override legacy backfill opt-in")
	}
}

func TestFreshOnlyApplicationCursorsStartAtCurrentInput(t *testing.T) {
	now := time.Date(2026, 10, 27, 6, 0, 0, 0, time.UTC)
	connection, raw, err := freshApplicationConnectionCursor(now)
	if err != nil || !strings.Contains(connection.WrittenAt, "2026-10-27T05:59:58Z") || string(raw) == "{}" || connection.SensorID != "\uffff" {
		t.Fatalf("connection cursor=%+v raw=%s err=%v", connection, raw, err)
	}
	observation, raw, err := freshApplicationObservationCursor(now)
	if err != nil || observation.WindowStart != "9999-12-31T23:59:59Z" || observation.SensorID != "\uffff" || string(raw) == "{}" {
		t.Fatalf("observation cursor=%+v raw=%s err=%v", observation, raw, err)
	}
}
