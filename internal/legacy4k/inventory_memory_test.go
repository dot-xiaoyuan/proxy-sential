package legacy4k

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func memoryInventory(rows int) OnlineInventory {
	in := OnlineInventory{InstanceID: "memory-replay", ObservedAt: time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC), Rows: make([]map[string]string, rows)}
	for i := range in.Rows {
		in.Rows[i] = map[string]string{"rad_online_id": strconv.Itoa(i + 1), "user_name": "alice", "ip": "192.0.2.1", "ipv6": "2001:db8::1", "ip6": "2001:db8::1", "user_mac": "02:00:00:00:00:01", "group_id": "1", "products_id": "1", "device_id": "endpoint"}
	}
	return in
}

func TestInventoryStatsDoesNotAllocateExpandedRecordMaps(t *testing.T) {
	in := memoryInventory(1000)
	var stats InventoryStats
	allocs := testing.AllocsPerRun(3, func() {
		var err error
		stats, err = in.Stats()
		if err != nil {
			panic(err)
		}
	})
	if stats.Accounts != 1 || stats.Sessions != 1000 || stats.AddressRecords != 2000 {
		t.Fatalf("counts=%+v", stats)
	}
	if allocs > 3000 {
		t.Fatalf("counting allocated full identity records: %.0f allocations", allocs)
	}
}

func TestInventoryStatsCountsCanonicalAccountAliases(t *testing.T) {
	in := memoryInventory(2)
	delete(in.Rows[0], "user_name")
	in.Rows[0]["username"] = " alice "
	delete(in.Rows[1], "user_name")
	in.Rows[1]["username"] = "bob"
	stats, err := in.Stats()
	if err != nil || stats.Accounts != 2 {
		t.Fatalf("valid aliases miscounted: %+v %v", stats, err)
	}
}

func BenchmarkInventoryStats(b *testing.B) {
	in := memoryInventory(2000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := in.Stats(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInventoryIdentityRecords(b *testing.B) {
	in := memoryInventory(2000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := in.IdentityRecords(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestInventoryExpansionMatchesFrozenR64Records(t *testing.T) {
	var golden struct {
		Inventory OnlineInventory     `json:"inventory"`
		Records   []map[string]string `json:"records"`
		Stats     InventoryStats      `json:"stats"`
	}
	raw, err := os.ReadFile("testdata/inventory-expansion-r64.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(golden.Inventory)
	records, stats, err := golden.Inventory.IdentityRecordsWithStats()
	if err != nil || !reflect.DeepEqual(records, golden.Records) || stats != golden.Stats {
		t.Fatalf("frozen records/session IDs or summary changed: stats=%+v err=%v records=%+v", stats, err, records)
	}
	counted, err := golden.Inventory.Stats()
	if err != nil || counted != stats {
		t.Fatalf("counting and expansion differ: %+v %+v %v", counted, stats, err)
	}
	after, _ := json.Marshal(golden.Inventory)
	if !bytes.Equal(before, after) {
		t.Fatal("input inventory mutated")
	}
}

func TestInventoryValidationReturnsNoPartialRecordsOrCounts(t *testing.T) {
	for _, name := range []string{"invalid_last_address", "session_key_collision", "address_limit"} {
		t.Run(name, func(t *testing.T) {
			in := memoryInventory(2)
			switch name {
			case "invalid_last_address":
				in.Rows[1]["ip6"] = "invalid"
			case "session_key_collision":
				login := "1790820000"
				in.Rows[0]["add_time"] = login
				key := OnlineSessionID(in.InstanceID, in.Rows[0]["rad_online_id"], login)
				in.Rows[1]["session_id"] = strings.TrimPrefix(key, in.InstanceID+":")
			case "address_limit":
				in = memoryInventory(MaxIdentityAddressRecords/3 + 1)
				for _, row := range in.Rows {
					row["ip6"] = "2001:db8::2"
				}
			}
			counted, countErr := in.Stats()
			records, expanded, expandErr := in.IdentityRecordsWithStats()
			if countErr == nil || expandErr == nil || countErr.Error() != expandErr.Error() || records != nil || counted != (InventoryStats{}) || expanded != (InventoryStats{}) {
				t.Fatalf("partial or inconsistent validation: records=%d counted=%+v expanded=%+v errors=%v/%v", len(records), counted, expanded, countErr, expandErr)
			}
		})
	}
}

func TestInventoryCompleteEmptySummary(t *testing.T) {
	in := memoryInventory(0)
	records, stats, err := in.IdentityRecordsWithStats()
	if err != nil || records == nil || len(records) != 0 || stats != (InventoryStats{}) {
		t.Fatalf("empty completeness lost: %+v %+v %v", records, stats, err)
	}
	counted, err := in.Stats()
	if err != nil || counted != stats {
		t.Fatalf("empty summaries differ: %+v %v", counted, err)
	}
}
