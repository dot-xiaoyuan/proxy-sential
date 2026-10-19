package store

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/risk"
)

// memoryFacts is an in-memory device_signal_facts table with the same predicates as the SQL source.
type memoryFacts struct {
	rows      map[string]DeviceSignal // signal_id -> fact
	updatedAt map[string]time.Time
}

func (m *memoryFacts) ChangedIPs(_ context.Context, since time.Time) ([]string, error) {
	set := map[string]bool{}
	for id, at := range m.updatedAt {
		if at.After(since) {
			set[m.rows[id].IP] = true
		}
	}
	return keys(set), nil
}

func (m *memoryFacts) IPsWithLastSeen(_ context.Context, after, through time.Time) ([]string, error) {
	set := map[string]bool{}
	for _, f := range m.rows {
		last, _ := time.Parse(time.RFC3339Nano, f.LastSeen)
		if last.After(after) && !last.After(through) {
			set[f.IP] = true
		}
	}
	return keys(set), nil
}

func (m *memoryFacts) WindowIPs(_ context.Context, from, through time.Time) ([]string, error) {
	set := map[string]bool{}
	for _, f := range m.rows {
		last, _ := time.Parse(time.RFC3339Nano, f.LastSeen)
		if !last.Before(from) && !last.After(through) {
			set[f.IP] = true
		}
	}
	return keys(set), nil
}

func (m *memoryFacts) FactsForIPs(_ context.Context, ips []string, from, through time.Time) (map[string][]DeviceSignal, error) {
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip] = true
	}
	out := map[string][]DeviceSignal{}
	for _, f := range m.rows {
		last, _ := time.Parse(time.RFC3339Nano, f.LastSeen)
		if want[f.IP] && !last.Before(from) && !last.After(through) {
			out[f.IP] = append(out[f.IP], f)
		}
	}
	for ip := range out {
		sortSignalsLikeQuery(out[ip])
	}
	return out, nil
}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// memoryInventory is an in-memory device_inventory_current.
type memoryInventory map[string]map[string]string // window -> ip -> compact inventory JSON

func (m memoryInventory) Upsert(_ context.Context, window string, item IPDeviceInventory) error {
	raw, _ := json.Marshal(compactCurrentInventory(item))
	if m[window] == nil {
		m[window] = map[string]string{}
	}
	m[window][item.IP] = string(raw)
	return nil
}

func (m memoryInventory) Delete(_ context.Context, window string, ips []string) error {
	for _, ip := range ips {
		delete(m[window], ip)
	}
	return nil
}

func (m memoryInventory) IPs(_ context.Context, window string) ([]string, error) {
	set := map[string]bool{}
	for ip := range m[window] {
		set[ip] = true
	}
	return keys(set), nil
}

// fullRebuild is the previous behaviour: every IP with facts in the window, nothing else.
func fullRebuild(facts *memoryFacts, now time.Time) memoryInventory {
	out := memoryInventory{}
	for _, window := range deviceInventoryWindows {
		_, duration, _ := NormalizeActivityWindow(window)
		byIP := map[string][]DeviceSignal{}
		for _, f := range facts.rows {
			last, _ := time.Parse(time.RFC3339Nano, f.LastSeen)
			if !last.Before(now.Add(-duration)) && !last.After(now) {
				byIP[f.IP] = append(byIP[f.IP], f)
			}
		}
		for ip, signals := range byIP {
			sortSignalsLikeQuery(signals)
			_ = out.Upsert(context.Background(), window, BuildDeviceInventoryFromSignals(ip, window, signals, risk.Snapshot{}))
		}
	}
	return out
}

// The incremental refresh must leave exactly what a full rebuild would, after every round: facts
// arrive, update, become due from the future and age out of each window.
func TestIncrementalDeviceInventoryMatchesFullRebuild(t *testing.T) {
	runIncrementalEquivalence(t, 20261019)
}

// A bootstrap that spans several rounds while facts keep changing converges to the same result.
func TestIncrementalDeviceInventoryMultiRoundBootstrap(t *testing.T) {
	saved := deviceInventoryBatch
	deviceInventoryBatch = 3
	defer func() { deviceInventoryBatch = saved }()
	runIncrementalEquivalence(t, 7)
}

func runIncrementalEquivalence(t *testing.T, seed int64) {
	r := rand.New(rand.NewSource(seed))
	for scenario := 0; scenario < 40; scenario++ {
		facts := &memoryFacts{rows: map[string]DeviceSignal{}, updatedAt: map[string]time.Time{}}
		inventory := memoryInventory{}
		var state deviceInventoryRefreshState
		now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
		kinds := []string{"mac", "hostname", "os_family", "vendor", "ttl"}
		for round := 0; round < 120; round++ {
			now = now.Add(time.Duration(30+r.Intn(600)) * time.Second)
			if r.Intn(20) == 0 {
				now = now.Add(time.Duration(r.Intn(30)) * time.Hour) // long gap: windows expire wholesale
			}
			for n := r.Intn(8); n > 0; n-- {
				ip := fmt.Sprintf("10.0.%d.%d", r.Intn(3), r.Intn(10))
				id := fmt.Sprintf("sig-%s-%d", ip, r.Intn(4))
				seen := now.Add(-time.Duration(r.Intn(3600*30)) * time.Second)
				if r.Intn(15) == 0 {
					seen = now.Add(time.Duration(r.Intn(1800)) * time.Second) // future-dated
				}
				old, exists := facts.rows[id]
				if exists {
					if prev, _ := time.Parse(time.RFC3339Nano, old.LastSeen); prev.After(seen) {
						seen = prev // last_seen = GREATEST(...)
					}
				}
				kind := kinds[r.Intn(len(kinds))]
				facts.rows[id] = DeviceSignal{SignalID: id, IP: ip, Source: "handshake", Kind: kind, Value: fmt.Sprint(r.Intn(5)), NormalizedValue: fmt.Sprint(r.Intn(5)),
					Strength: []string{"strong", "medium", "weak"}[r.Intn(3)], Confidence: 0.5 + r.Float64()/2, Weight: 10 + r.Intn(90),
					FirstSeen: seen.Add(-time.Hour).Format(time.RFC3339Nano), LastSeen: seen.Format(time.RFC3339Nano), SeenCount: 1 + r.Intn(9)}
				facts.updatedAt[id] = now
			}
			var err error
			state, err = refreshDeviceInventoryIncrementally(context.Background(), facts, inventory, state, now)
			if err != nil {
				t.Fatal(err)
			}
			if !state.Bootstrapped {
				continue
			}
			want := fullRebuild(facts, now)
			for _, window := range deviceInventoryWindows {
				if !reflect.DeepEqual(nonNil(inventory[window]), nonNil(want[window])) {
					t.Fatalf("scenario %d round %d window %s at %s:\nincremental=%v\nfull=%v", scenario, round, window, now.Format(time.RFC3339), keysOf(inventory[window]), keysOf(want[window]))
				}
			}
		}
	}
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func keysOf(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The SQL source uses the same boundaries as the in-memory one and only indexed predicates.
func TestDeviceInventorySourceQueries(t *testing.T) {
	for name, pair := range map[string][2]string{
		"changed":   {deviceFactsChangedSQL, "updated_at>$2"},
		"crossed":   {deviceFactsCrossedSQL, "last_seen>$2 AND last_seen<=$3"},
		"window":    {deviceFactsWindowIPsSQL, "last_seen>=$2 AND last_seen<=$3"},
		"facts":     {deviceFactsForIPsSQL, "ip=ANY($2::inet[]) AND last_seen>=$3 AND last_seen<=$4"},
		"delete":    {deviceInventoryDeleteSQL, `"window"=$2 AND host(ip)=ANY($3::text[])`},
		"inventory": {deviceInventoryIPsSQL, `"window"=$2`},
	} {
		if !strings.Contains(pair[0], pair[1]) || !strings.Contains(pair[0], "sensor_id=$1") {
			t.Fatalf("%s query lacks %q: %s", name, pair[1], pair[0])
		}
	}
	if !strings.Contains(deviceFactsForIPsSQL, "ORDER BY ip ASC, last_seen DESC, signal_id ASC") {
		t.Fatal("per-IP facts must keep the full rebuild's signal order")
	}
	if deviceInventoryChangeOverlap < 2*identityWorkBudget {
		t.Fatalf("overlap %s does not cover a late identity commit (%s budget)", deviceInventoryChangeOverlap, identityWorkBudget)
	}
}
