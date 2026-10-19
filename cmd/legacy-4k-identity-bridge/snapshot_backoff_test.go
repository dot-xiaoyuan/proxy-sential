package main

import (
	"testing"
	"time"
)

// A failed snapshot re-reads and re-sends the whole online inventory. Retrying every ten seconds
// while the endpoint is overloaded made each failure add more load, so retries back off.
func TestSnapshotRetryBacksOffAndCaps(t *testing.T) {
	cases := map[int]time.Duration{0: 10 * time.Second, 1: 10 * time.Second, 2: 20 * time.Second, 3: 40 * time.Second, 5: 160 * time.Second, 6: 5 * time.Minute, 40: 5 * time.Minute}
	for failures, want := range cases {
		if got := snapshotRetryDelay(failures); got != want {
			t.Fatalf("failures=%d delay=%s want %s", failures, got, want)
		}
	}
}
