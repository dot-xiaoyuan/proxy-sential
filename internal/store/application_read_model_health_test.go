package store

import "testing"

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
