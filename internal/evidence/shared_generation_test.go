package evidence

import (
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"reflect"
	"testing"
	"time"
)

func TestSharedWindowsSplitGenerationBeforeAggregation(t *testing.T) {
	from := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	boundary := from.Add(10 * time.Second)
	to := from.Add(time.Minute)
	makeEvent := func(id string, at time.Time, ttl int) normalized.Event {
		return normalized.Event{EventID: id, Source: "capture", Type: "device", Timestamp: at.Format(time.RFC3339Nano), Subject: map[string]any{"ip": "192.0.2.1", "campus_id": "office"}, Observer: map[string]any{"sensor_id": "s"}, Flow: map[string]any{"direction": "outbound"}, Payload: map[string]any{"access_domain": "lan", "ttl": ttl}}
	}
	events := []normalized.Event{makeEvent("old", from.Add(time.Second), 63), makeEvent("new", boundary, 127), makeEvent("after", boundary.Add(time.Second), 127)}
	sessions := []policy.Session{{ID: "old", IP: "192.0.2.1", CampusID: "office", AccessDomain: "lan", StartedAt: from, EndedAt: boundary}, {ID: "new", IP: "192.0.2.1", CampusID: "office", AccessDomain: "lan", StartedAt: boundary}}
	windows := SharedWindowsBySession(events, sessions, from, to, true)
	if len(windows) != 2 || len(windows[0].TTLPaths) != 1 || len(windows[1].TTLPaths) != 1 || windows[1].From != boundary {
		t.Fatal("generations mixed or boundary event assigned backwards", windows)
	}
	reversed := []normalized.Event{events[2], events[1], events[0]}
	if !reflect.DeepEqual(windows, SharedWindowsBySession(reversed, sessions, from, to, true)) {
		t.Fatal("unstable replay ordering")
	}
	// Altered retries may not evade conflict detection by crossing generations.
	changed := events[0]
	changed.Timestamp = boundary.Add(time.Second).Format(time.RFC3339Nano)
	windows = SharedWindowsBySession(append(events, changed), sessions, from, to, true)
	for _, window := range windows {
		if len(window.Conflicts) == 0 {
			t.Fatal("generation split concealed changed duplicate")
		}
	}
}

func TestSharedIPv6HopLimitNotIPv4PenaltySignal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	event := normalized.Event{EventID: "v6-hop", Source: "packet-sidecar", Type: "device", Timestamp: now.Format(time.RFC3339Nano), Subject: map[string]any{"ip": "2001:db8::1", "campus_id": "office"}, Observer: map[string]any{"sensor_id": "s"}, Flow: map[string]any{"direction": "outbound", "ip_version": 6}, Payload: map[string]any{"access_domain": "lan", "ttl": 63, "hop_limit": 63}}
	windows := SharedWindows([]normalized.Event{event}, now.Add(-time.Minute), now, true)
	if len(windows) != 1 || len(windows[0].TTLPaths) != 0 {
		t.Fatal("unverified IPv6 rule participated in IPv4 shared basis")
	}
}
