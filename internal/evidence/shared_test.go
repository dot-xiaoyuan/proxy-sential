package evidence

import (
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestSharedWindowsScopeDedupAndDirection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	makeEvent := func(id, sensor, direction string, ttl int) normalized.Event {
		return normalized.Event{EventID: id, Type: "device", Source: "capture", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "collector_instance_id": "boot"}, Subject: map[string]any{"ip": "192.0.2.1", "campus_id": "campus"}, Flow: map[string]any{"direction": direction}, Payload: map[string]any{"ttl": ttl, "access_domain": "nas"}}
	}
	a := makeEvent("same", "one", "outbound", 63)
	b := makeEvent("same", "two", "outbound", 127)
	inbound := makeEvent("reply", "one", "inbound", 127)
	events := []normalized.Event{a, b, a, inbound}
	rows := SharedWindows(events, now.Add(-time.Minute), now, true)
	if len(rows) != 2 {
		t.Fatal("sensor mixing or duplicate loss", rows)
	}
	for _, w := range rows {
		if len(w.TTLPaths) != 1 || !w.Complete || len(w.EventIDs) == 0 {
			t.Fatal(w)
		}
	}
	reverse := []normalized.Event{inbound, a, b, a}
	if got := SharedWindows(reverse, now.Add(-time.Minute), now, true); !reflect.DeepEqual(got, rows) {
		t.Fatal("reordering changed windows")
	}
	altered := makeEvent("same", "one", "outbound", 127)
	if got := SharedWindows([]normalized.Event{a, altered}, now.Add(-time.Minute), now, true); len(got) != 1 || len(got[0].Conflicts) == 0 {
		t.Fatal("same event changed without conflict", got)
	}
	if got := SharedWindows([]normalized.Event{a}, now.Add(-time.Minute), now, false); got[0].Complete {
		t.Fatal("partial query became complete")
	}
}
