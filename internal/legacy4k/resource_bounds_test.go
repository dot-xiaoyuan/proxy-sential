package legacy4k

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOnlineIdentityRejectsOversizedProjectedField(t *testing.T) {
	in := OnlineInventory{InstanceID: "replay", ObservedAt: time.Now().UTC(), Rows: []map[string]string{{"rad_online_id": "one", "user_name": "alice", "ip": "192.0.2.1", "device_id": strings.Repeat("x", 4097)}}}
	if _, err := in.IdentityRecords(); !errors.Is(err, ErrOnlineResourceLimit) {
		t.Fatal("oversized identity projection accepted")
	}
}

func TestOnlineIdentityRejectsAggregateProjectionBeforeExpansion(t *testing.T) {
	in := OnlineInventory{InstanceID: "replay", ObservedAt: time.Now().UTC()}
	// Each field is individually bounded, but the complete source exceeds 64MiB.
	value := strings.Repeat("x", 4096)
	for i := 0; i < 17000; i++ {
		in.Rows = append(in.Rows, map[string]string{"rad_online_id": strconv.Itoa(i + 1), "user_name": "alice", "ip": "192.0.2.1", "device_id": value})
	}
	if _, err := in.IdentityRecords(); !errors.Is(err, ErrOnlineResourceLimit) {
		t.Fatal("aggregate identity projection accepted")
	}
}

func TestOnlineProjectionCapacityExactBoundary(t *testing.T) {
	rows := []map[string]string{}
	remaining := MaxOnlineProjectionBytes
	for remaining > 0 {
		count := min(remaining, MaxOnlineFieldBytes+1)
		rows = append(rows, map[string]string{"x": strings.Repeat("v", count-1)})
		remaining -= count
	}
	if err := validateOnlineProjection(rows); err != nil {
		t.Fatal("exact aggregate boundary rejected", err)
	}
	rows = append(rows, map[string]string{"x": ""})
	if err := validateOnlineProjection(rows); !errors.Is(err, ErrOnlineResourceLimit) {
		t.Fatal("aggregate boundary plus one accepted", err)
	}
}

func TestOnlineProjectionRowCountBoundary(t *testing.T) {
	rows := make([]map[string]string, 100000)
	if err := validateOnlineProjection(rows); err != nil {
		t.Fatal(err)
	}
	if err := validateOnlineProjection(append(rows, nil)); !errors.Is(err, ErrOnlineResourceLimit) {
		t.Fatal("source row count unbounded", err)
	}
}
