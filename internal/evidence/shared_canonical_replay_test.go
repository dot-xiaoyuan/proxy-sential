package evidence

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
)

func canonicalSharedEvent(id, ip string, at time.Time, ttl int) normalized.Event {
	return normalized.Event{EventID: id, Source: "capture", Type: "device", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "s", "collector_instance_id": "boot"}, Subject: map[string]any{"ip": ip, "campus_id": "c"}, Flow: map[string]any{"direction": "outbound"}, Payload: map[string]any{"access_domain": "nas", "ttl": ttl}}
}

func TestSharedCanonicalEncodingFailureReplay(t *testing.T) {
	from := time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC)
	boundary := from.Add(10 * time.Second)
	to := from.Add(time.Minute)
	cases := map[string]func(*normalized.Event){
		"nan":                 func(e *normalized.Event) { e.Confidence = math.NaN() },
		"infinity":            func(e *normalized.Event) { e.Confidence = math.Inf(1) },
		"raw-channel":         func(e *normalized.Event) { e.RawRef = map[string]any{"bad": make(chan int)} },
		"payload-function":    func(e *normalized.Event) { e.Payload["bad"] = func() {} },
		"invalid-json-number": func(e *normalized.Event) { e.RawRef = map[string]any{"bad": json.Number("bad")} },
		"cyclic-map":          func(e *normalized.Event) { m := map[string]any{}; m["cycle"] = m; e.RawRef = m },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			good := canonicalSharedEvent("good", "192.0.2.1", from.Add(time.Second), 63)
			bad := canonicalSharedEvent("changed", "192.0.2.1", boundary.Add(time.Second), 127)
			damage(&bad)
			events := []normalized.Event{good, bad}
			sessions := []policy.Session{{IP: good.Subject["ip"].(string), CampusID: "c", AccessDomain: "nas", StartedAt: from, EndedAt: boundary}, {IP: good.Subject["ip"].(string), CampusID: "c", AccessDomain: "nas", StartedAt: boundary}}
			for _, rows := range [][]sharedaccess.Window{SharedWindows(events, from, to, true), SharedWindowsBySession(events, sessions, from, to, true)} {
				if len(rows) != 1 {
					t.Fatalf("invalid event participated in features: %+v", rows)
				}
				for _, w := range rows {
					if w.Complete || !slices.Contains(w.Conflicts, "standard_event_encoding_failed") || !reflect.DeepEqual(w.EventIDs, []string{"good"}) || len(w.TTLPaths) != 1 {
						t.Fatalf("encoding failure became usable evidence: %+v", w)
					}
					w.CoverageVerified = true
					result := sharedaccess.Evaluate(w, sharedaccess.Config{}, sessions, to, time.Minute)
					input := sharedaccess.Input("fixture-account", []sharedaccess.Result{result}, "manual")
					if result.State != "insufficient" || result.Confidence != 0 || input.Known || input.Violated {
						t.Fatalf("invalid canonical data became account policy input: %+v %+v", result, input)
					}
					encoded, err := json.Marshal(w)
					if err != nil || len(encoded) == 0 {
						t.Fatalf("safe diagnostic window not serializable: %v", err)
					}
				}
			}
			if len(SharedWindows([]normalized.Event{bad}, from, to, true)) != 0 {
				t.Fatal("invalid-only query formed evidence")
			}
			if _, err := json.Marshal(bad); err == nil {
				t.Fatal("test did not preserve original invalid event")
			}
			reversed := []normalized.Event{bad, good}
			if !reflect.DeepEqual(SharedWindowsBySession(events, sessions, from, to, true), SharedWindowsBySession(reversed, sessions, from, to, true)) {
				t.Fatal("error replay depends on input ordering")
			}
		})
	}
}

func TestSharedCanonicalSessionAddressReplay(t *testing.T) {
	from := time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC)
	boundary := from.Add(10 * time.Second)
	to := from.Add(time.Minute)
	for _, pair := range [][2]string{{"192.0.2.1", "::ffff:192.0.2.1"}, {"::ffff:192.0.2.1", "192.0.2.1"}, {"2001:db8::1", "2001:0db8:0:0:0:0:0:1"}, {"2001:0db8:0:0:0:0:0:1", "2001:db8::1"}} {
		t.Run(pair[0]+"-"+pair[1], func(t *testing.T) {
			events := []normalized.Event{canonicalSharedEvent("old", pair[1], from.Add(time.Second), 63), canonicalSharedEvent("new", pair[1], boundary, 127)}
			sessions := []policy.Session{{IP: pair[0], CampusID: "c", AccessDomain: "nas", StartedAt: from, EndedAt: boundary}, {IP: pair[0], CampusID: "c", AccessDomain: "nas", StartedAt: boundary}}
			rows := SharedWindowsBySession(events, sessions, from, to, true)
			if len(rows) != 2 || rows[0].To.After(boundary.Add(-time.Nanosecond)) || rows[1].From != boundary || !reflect.DeepEqual(rows[0].EventIDs, []string{"old"}) || !reflect.DeepEqual(rows[1].EventIDs, []string{"new"}) {
				t.Fatalf("equivalent address bypassed generation boundary: %+v", rows)
			}
		})
	}
}
