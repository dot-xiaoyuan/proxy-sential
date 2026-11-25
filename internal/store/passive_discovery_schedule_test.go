package store

import (
	"context"
	"testing"
	"time"
)

func TestPassiveDiscoveryFinishRejectsPartialAndStaleCheckpoint(t *testing.T) {
	ctx := context.Background()
	store := &DBStore{pg: privateMigratedTestPostgres(t)}
	t.Setenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_DHCP_ONLY", "true")
	const sensor = "schedule-replay"
	claim, ok, err := store.claimPassiveDiscovery(ctx, sensor, "first")
	if err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	next := claim
	next.Timestamp = next.Timestamp.Add(time.Minute)
	stats := passiveDiscoveryBatchStats{Processed: 1, Protocols: map[string]int{"dhcp": 1}, Reasons: map[string]int{}}
	if _, err := store.pg.db.Exec("ALTER TABLE passive_discovery_state ADD CHECK (processed_events < 1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finishPassiveDiscovery(ctx, sensor, next, stats, nil); err == nil {
		t.Fatal("injected sensor state failure was accepted")
	}
	checkSource := func() {
		t.Helper()
		var at time.Time
		if err := store.pg.db.QueryRow("SELECT cursor_timestamp FROM passive_discovery_source_cursors WHERE sensor_id=$1", sensor).Scan(&at); err != nil || !at.Equal(claim.Timestamp) {
			t.Errorf("source cursor after failed commit = %v, want %v, err=%v", at, claim.Timestamp, err)
		}
	}
	checkSource()
	if _, err := store.pg.db.Exec("UPDATE passive_discovery_state SET lease_owner='second' WHERE sensor_id=$1", sensor); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finishPassiveDiscovery(ctx, sensor, next, stats, nil); err == nil {
		t.Error("superseded owner reported success")
	}
	checkSource()
}

func TestPassiveDiscoverySuccessfulPollDelay(t *testing.T) {
	cutoff := time.Now().UTC()
	old := cutoff.Add(-time.Hour)
	near := cutoff.Add(-2 * time.Second)
	for _, tc := range []struct {
		name     string
		from, to passiveDiscoveryCursor
		slowest  time.Time
		full     bool
		want     time.Duration
	}{
		{"short batch with more eligible work", passiveDiscoveryCursor{Timestamp: old}, passiveDiscoveryCursor{Timestamp: old.Add(time.Second)}, old, false, 0},
		{"empty source crossed backlog with other sources behind", passiveDiscoveryCursor{Timestamp: old}, passiveDiscoveryCursor{Timestamp: cutoff}, old, false, 0},
		{"last empty source caught up", passiveDiscoveryCursor{Timestamp: old}, passiveDiscoveryCursor{Timestamp: cutoff}, near, false, time.Second},
		{"other inactive source remains old", passiveDiscoveryCursor{Timestamp: near}, passiveDiscoveryCursor{Timestamp: cutoff}, old, false, time.Second},
		{"no progress despite backlog", passiveDiscoveryCursor{Timestamp: old}, passiveDiscoveryCursor{Timestamp: old}, old, false, time.Second},
		{"full but same cursor", passiveDiscoveryCursor{Timestamp: old, EventID: "a"}, passiveDiscoveryCursor{Timestamp: old, EventID: "a"}, old, true, time.Second},
		{"same timestamp new row", passiveDiscoveryCursor{Timestamp: old, EventID: "a"}, passiveDiscoveryCursor{Timestamp: old, EventID: "b"}, old, false, 0},
		{"full near head", passiveDiscoveryCursor{Timestamp: near, EventID: "a"}, passiveDiscoveryCursor{Timestamp: near, EventID: "b"}, near, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := passiveDiscoverySuccessfulPollDelay(tc.from, tc.to, cutoff, tc.slowest, tc.full); got != tc.want {
				t.Fatalf("poll delay = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPassiveDiscoveryEmptySourceCatchupRotation(t *testing.T) {
	ctx := context.Background()
	store := &DBStore{pg: privateMigratedTestPostgres(t)}
	t.Setenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_DHCP_ONLY", "")
	const sensor = "empty-rotation"
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	old := cutoff.Add(-time.Hour)
	if _, err := store.pg.db.Exec("INSERT INTO passive_discovery_state(sensor_id,cursor_timestamp) VALUES($1,$2)", sensor, old); err != nil {
		t.Fatal(err)
	}
	var totalDelay time.Duration
	seen := map[string]bool{}
	sources := passiveDiscoverySources()
	for range sources {
		claim, ok, err := store.claimPassiveDiscovery(ctx, sensor, "replay")
		if err != nil || !ok || seen[claim.Source] || !claim.Timestamp.Equal(old) {
			t.Fatalf("unexpected claim %+v, acquired=%v err=%v", claim, ok, err)
		}
		seen[claim.Source] = true
		next := claim
		next.Timestamp = cutoff
		empty := passiveDiscoveryBatchStats{Protocols: map[string]int{}, Reasons: map[string]int{}}
		slowest, err := store.finishPassiveDiscovery(ctx, sensor, next, empty, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := old
		if len(seen) == len(sources) {
			want = cutoff
		}
		if !slowest.Equal(want) {
			t.Fatalf("after %d sources slowest = %v, want %v", len(seen), slowest, want)
		}
		totalDelay += passiveDiscoverySuccessfulPollDelay(claim, next, cutoff, slowest, false)
	}
	if totalDelay != time.Second {
		t.Fatalf("%d empty sources accrued %v of poll delay, want one final 1s idle poll", len(seen), totalDelay)
	}
	var processed, emitted int64
	if err := store.pg.db.QueryRow("SELECT processed_events,emitted_observations FROM passive_discovery_state WHERE sensor_id=$1", sensor).Scan(&processed, &emitted); err != nil || processed != 0 || emitted != 0 {
		t.Fatalf("empty windows produced events=%d observations=%d err=%v", processed, emitted, err)
	}
}
