package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"runtime"
	"testing"
	"time"
)

// These programmed protocol profiles exercise the consumer, not live packet
// parsing. Homogeneous sharing is intentionally recorded as an undetected case.
func TestCampusSharedReplay(t *testing.T) {
	rounds := 1
	if os.Getenv("SENTINEL_CAMPUS_STRESS") == "1" {
		rounds = 1000
	}
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	cfg := sharedaccess.Config{Version: "campus-lab", Sources: []sharedaccess.Source{{SensorID: "lab", Source: "synthetic", CampusID: "campus", AccessDomain: "nas"}}}
	names := []string{"normal", "multi_browser", "ua_emulation", "roaming", "random_mac", "shared_cdn", "heterogeneous_hotspot", "homogeneous_hotspot", "expired_identity", "duplicate"}
	wants := []string{"not_matched", "not_matched", "insufficient", "insufficient", "not_matched", "not_matched", "basis_present", "not_matched", "insufficient", "not_matched"}
	states := map[string]map[string]int{}
	var peak uint64
	start := time.Now()
	for round := 0; round < rounds; round++ {
		events := make([]normalized.Event, 0, 1000)
		sessions := make([]policy.Session, len(names))
		for scenario, name := range names {
			ip := fmt.Sprintf("192.0.2.%d", scenario+1)
			sessions[scenario] = policy.Session{ID: name, AccountID: name, EndpointID: "upstream-" + name, IP: ip, CampusID: "campus", AccessDomain: "nas", Source: "auth", SensorID: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}
			if name == "expired_identity" {
				sessions[scenario].Confirmations = nil
				sessions[scenario].ConfirmedAt = now.Add(-time.Hour)
			}
			for i := 0; i < 100; i++ {
				ua, stack, ttl := "Mozilla/5.0 (Android)", "stack-a", 63
				if i%2 == 1 {
					switch name {
					case "multi_browser":
						stack = "stack-b"
					case "ua_emulation":
						ua = "Mozilla/5.0 (Windows NT 10.0)"
					case "roaming":
						ttl = 62
					case "heterogeneous_hotspot":
						ua = "Mozilla/5.0 (Windows NT 10.0)"
						stack = "stack-b"
						ttl = 127
					}
				}
				e := normalized.Event{EventID: fmt.Sprintf("%d-%d-%d", round, scenario, i), Type: "device", Source: "synthetic", Timestamp: now.Add(-time.Duration(100-i) * 200 * time.Millisecond).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "lab", "collector_instance_id": fmt.Sprintf("run-%d", round)}, Subject: map[string]any{"ip": ip, "campus_id": "campus"}, Flow: map[string]any{"direction": "outbound"}, Payload: map[string]any{"access_domain": "nas", "ttl": ttl, "user_agent": ua, "ja3": stack}}
				if name == "random_mac" {
					e.Subject["mac"] = fmt.Sprintf("02:00:00:00:00:%02x", i)
					e.Payload["hostname"] = fmt.Sprintf("device-%d", i)
				}
				if name == "shared_cdn" {
					e.Payload["host"] = fmt.Sprintf("cdn-%d.example.test", i)
				}
				if name == "duplicate" && i%2 == 1 {
					e = events[len(events)-1]
				}
				events = append(events, e)
			}
		}
		windows := SharedWindows(events, now.Add(-time.Minute), now, true)
		if len(windows) != len(names) {
			t.Fatalf("scope lost: %d", len(windows))
		}
		for _, w := range windows {
			var idx int
			for i := range names {
				if sessions[i].IP == w.IP {
					idx = i
					break
				}
			}
			result := sharedaccess.Evaluate(w, cfg, sessions, now, 10*time.Minute)
			if result.State != wants[idx] {
				t.Fatalf("%s: state %s want %s reasons %v", names[idx], result.State, wants[idx], result.Reasons)
			}
			if result.DeviceLowerBound > 1 {
				t.Fatal("downstream identities invented")
			}
			if states[names[idx]] == nil {
				states[names[idx]] = map[string]int{}
			}
			states[names[idx]][result.State]++
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > peak {
			peak = m.HeapAlloc
		}
	}
	summary := map[string]any{"events": rounds * 1000, "seconds": time.Since(start).Seconds(), "sampled_peak_go_heap_bytes": peak, "states": states, "limitation": "synthetic standard-event consumer replay; homogeneous hotspot undetected; excludes capture, database, scheduling and policy delivery"}
	raw, _ := json.Marshal(summary)
	t.Log(string(raw))
}
