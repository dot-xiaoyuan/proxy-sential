package sharedaccess

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestTTLPathVariationCannotCorroborateSharedBehavior(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name  string
		paths []string
		once  string
		want  bool
	}{
		{"hop_variation", []string{"initial=64,hops=0", "initial=64,hops=1"}, "", false},
		{"opposite_direction", []string{"direction=outbound,initial=64,hops=1", "direction=inbound,initial=128,hops=1"}, "", false},
		{"transient_other_family", []string{"initial=64,hops=0", "initial=64,hops=1", "initial=128,hops=1"}, "initial=128,hops=1", false},
		{"repeated_other_family", []string{"initial=64,hops=1", "initial=128,hops=1"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := repeatedBehaviorWindow(now, map[string][]string{"ttl_path": tc.paths, "tcp_stack": {"tcp-one", "tcp-two"}})
			if tc.once != "" {
				sample := w.Samples["ttl_path"][tc.once]
				sample.Count = 1
				w.Samples["ttl_path"][tc.once] = sample
			}
			result, present := AssessBehavior("ttl-replay", "", w, BehaviorRouterContext{})
			if present != tc.want {
				t.Fatalf("presence=%v want=%v assessment=%+v", present, tc.want, result)
			}
			if tc.want && (result.Status == "confirmed" || result.Confidence > 59) {
				t.Fatal("weak host families became sharing proof", result)
			}
		})
	}
}

func TestTTLPathVariationCannotCompleteAccountSharingBasis(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := Config{Version: "ttl-replay", Sources: []Source{{SensorID: "sensor", Source: "dpi", CampusID: "campus", AccessDomain: "nas"}}}
	session := policy.Session{ID: "generation", AccountID: "account", IP: "192.0.2.10", CampusID: "campus", AccessDomain: "nas", Source: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}
	for _, tc := range []struct {
		name  string
		paths []string
		want  string
	}{
		{"hop_variation", []string{"initial=64,hops=0", "initial=64,hops=1"}, "insufficient"},
		{"opposite_direction", []string{"direction=outbound,initial=64,hops=1", "direction=inbound,initial=128,hops=1"}, "insufficient"},
		{"repeated_initial_families", []string{"initial=64,hops=1", "initial=128,hops=1"}, "basis_present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := repeatedBehaviorWindow(now, map[string][]string{"ttl_path": tc.paths, "ua_os": {"Android", "Windows"}, "tls_stack": {"tls-one", "tls-two"}})
			w.Sources = []string{"dpi"}
			w.From = now.Add(-time.Minute)
			result := Evaluate(w, cfg, []policy.Session{session}, now, 10*time.Minute)
			if result.State != tc.want {
				t.Fatal("path variation completed sharing basis", result)
			}
			if tc.want != "basis_present" {
				for _, group := range result.SignalGroups {
					if group == "ttl_path" {
						t.Fatal("path variation counted as independent TTL group", result)
					}
				}
			}
		})
	}
}
