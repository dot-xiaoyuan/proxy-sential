package evidence

import (
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestSharedSamplesDeduplicateEventsAndIgnorePacketCount(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	e := normalized.Event{EventID: "aggregate", Type: "device", Source: "packet-sidecar", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "s", "collector_instance_id": "boot"}, Subject: map[string]any{"ip": "192.0.2.1", "campus_id": "c"}, Flow: map[string]any{"direction": "outbound"}, Payload: map[string]any{"access_domain": "nas", "ttl": 63, "observed_count": 100000, "user_agent": "Mozilla/5.0 (Android)"}}
	events := make([]normalized.Event, 100)
	for i := range events {
		events[i] = e
	}
	windows := SharedWindows(events, now.Add(-time.Minute), now, true)
	if len(windows) != 1 {
		t.Fatal("missing window")
	}
	samples := windows[0].Samples["ua_os"]
	if len(samples) != 1 {
		t.Fatal("missing feature")
	}
	for _, sample := range samples {
		if sample.Count != 1 || len(sample.Buckets) != 1 {
			t.Fatalf("retries or packets inflated evidence: %+v", sample)
		}
	}
}
