package store

import (
	"testing"
	"time"
)

func TestPassiveDiscoveryReadCutoff(t *testing.T) {
	now := time.Date(2026, 11, 5, 13, 30, 0, 0, time.UTC)
	t.Setenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_HOLDBACK", "")
	cutoff, err := passiveDiscoveryReadCutoff(now)
	if err != nil || !cutoff.Equal(now.Add(-2*time.Minute)) {
		t.Fatalf("default cutoff = %s, %v", cutoff, err)
	}
	t.Setenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_HOLDBACK", "5m")
	cutoff, err = passiveDiscoveryReadCutoff(now)
	if err != nil || !cutoff.Equal(now.Add(-5*time.Minute)) {
		t.Fatalf("configured cutoff = %s, %v", cutoff, err)
	}
	for _, invalid := range []string{"0", "20s", "31m", "garbage"} {
		t.Setenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_HOLDBACK", invalid)
		if _, err := passiveDiscoveryReadCutoff(now); err == nil {
			t.Fatalf("accepted invalid holdback %q", invalid)
		}
	}
}
