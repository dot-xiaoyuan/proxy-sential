package sharedaccess

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestSharedTemporalEvidenceRequired(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	cfg := Config{Version: "test", Sources: []Source{{SensorID: "s", Source: "dpi", CampusID: "c", AccessDomain: "nas"}}}
	session := policy.Session{ID: "generation", AccountID: "a", IP: "192.0.2.1", CampusID: "c", AccessDomain: "nas", Source: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}
	for _, tc := range []struct {
		name        string
		count       int
		left, right []int64
		want        string
	}{
		{"repeated coexistence", 3, []int64{now.Unix()/5 - 2, now.Unix()/5 - 1}, []int64{now.Unix()/5 - 2, now.Unix()/5 - 1}, "basis_present"},
		{"only two observations", 2, []int64{now.Unix()/5 - 2, now.Unix()/5 - 1}, []int64{now.Unix()/5 - 2, now.Unix()/5 - 1}, "insufficient"},
		{"one bucket despite packet volume", 3, []int64{now.Unix()/5 - 1}, []int64{now.Unix()/5 - 1}, "insufficient"},
		{"sequential profiles", 3, []int64{now.Unix()/5 - 4, now.Unix()/5 - 3}, []int64{now.Unix()/5 - 2, now.Unix()/5 - 1}, "insufficient"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := Window{ID: "window", RuleVersion: RuleVersion, IP: session.IP, SensorID: "s", CampusID: "c", AccessDomain: "nas", Sources: []string{"dpi"}, From: now.Add(-time.Minute), To: now, LastObservedAt: now, Complete: true, EventIDs: []string{"event"}, UAOS: []string{"Android", "Windows"}, TTLPaths: []string{"63", "127"}, TLSStacks: []string{"one", "two"}}
			w.Samples = map[string]map[string]FeatureSample{}
			for family, values := range map[string][]string{"ua_os": w.UAOS, "ttl_path": w.TTLPaths, "tls_stack": w.TLSStacks} {
				w.Samples[family] = map[string]FeatureSample{values[0]: {Count: tc.count, Buckets: tc.left}, values[1]: {Count: tc.count, Buckets: tc.right}}
			}
			r := Evaluate(w, cfg, []policy.Session{session}, now, 10*time.Minute)
			if r.State != tc.want {
				t.Fatalf("got %s reasons %v", r.State, r.Reasons)
			}
		})
	}
}
