package controlplane

import (
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestIdentitySnapshotClockSkewPreservesObservation(t *testing.T) {
	now := time.Date(2026, 10, 6, 7, 14, 52, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		delta time.Duration
		valid bool
	}{
		{"redis_three_milliseconds_ahead", 3 * time.Millisecond, true},
		{"one_second_boundary", time.Second, true},
		{"excessive_future", time.Second + time.Microsecond, false},
		{"seven_day_boundary", -7 * 24 * time.Hour, true},
		{"expired", -7*24*time.Hour - time.Microsecond, false},
		{"sub_microsecond", time.Nanosecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := 1
			at := now.Add(tc.delta)
			snapshot, err := prepareIdentitySnapshot(identitySnapshotRequest{
				IdentityScope: store.IdentityScope{Source: "srun4k:clock-replay", SensorID: "replay"},
				ObservedAt:    at, IntervalSeconds: 21600, Complete: true, ExpectedCount: &count,
				Records: []map[string]string{{"session_id": "3900a8c0-d7", "account_id": "yuantong", "ip": "192.168.0.57"}},
			}, "clock-replay", now)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid && (!snapshot.ObservedAt.Equal(at) || len(snapshot.Events) != 1) {
				t.Fatalf("source observation changed: %+v", snapshot)
			}
		})
	}
}
