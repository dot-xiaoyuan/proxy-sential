package store

import (
	"testing"
	"time"
)

func TestDeviceViewReplay(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		at   string
		want bool
	}{{now.Format(time.RFC3339), true}, {now.Add(-24 * time.Hour).Format(time.RFC3339), true}, {now.Add(-24*time.Hour - time.Second).Format(time.RFC3339), false}, {now.Add(time.Second).Format(time.RFC3339), false}, {"", false}} {
		if got := deviceInView(EndpointDeviceInventory{LastSeen: tc.at}, Query{View: "recent", Window: "24h"}, now); got != tc.want {
			t.Errorf("%s: %v", tc.at, got)
		}
		if !deviceInView(EndpointDeviceInventory{LastSeen: tc.at}, Query{}, now) {
			t.Fatal("legacy history changed")
		}
	}
}
