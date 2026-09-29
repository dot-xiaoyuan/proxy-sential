package sharedaccess

import (
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

func TestSharedAccessReplayBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	cfg := Config{Version: "test", Sources: []Source{{SensorID: "capture", Source: "normalized-dpi", CampusID: "campus", AccessDomain: "nas"}}}
	session := policy.Session{ID: "s1", AccountID: "a", EndpointID: "phone", IP: "192.0.2.1", Source: "auth", SensorID: "auth", CampusID: "campus", AccessDomain: "nas", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}
	baseline := Window{ID: "shared-window", RuleVersion: RuleVersion, IP: "192.0.2.1", SensorID: "capture", CampusID: "campus", AccessDomain: "nas", Sources: []string{"normalized-dpi"}, From: now.Add(-time.Minute), To: now, LastObservedAt: now, Complete: true, EventIDs: []string{"record-1"}, UAOS: []string{"Android"}, TTLPaths: []string{"out:64:1"}, TLSStacks: []string{"stack1"}, DHCPProfiles: []string{"Android"}}
	for _, name := range []string{"hotspot", "hotspot_unknown_device", "single", "multi_browser", "shared_cdn", "ttl_only", "ua_only", "random_mac", "roaming", "missing_scope", "untrusted_source", "stale", "partial", "identity_conflict", "ip_rebound", "evidence_conflict"} {
		t.Run(name, func(t *testing.T) {
			w := baseline
			ss := []policy.Session{session}
			c := cfg
			want := "not_matched"
			switch name {
			case "hotspot", "hotspot_unknown_device":
				if name == "hotspot_unknown_device" {
					ss[0].EndpointID = ""
				}
				w.UAOS = []string{"Android", "Windows"}
				w.TTLPaths = []string{"out:64:1", "out:128:1"}
				w.DHCPProfiles = []string{"Android", "Windows"}
				want = "basis_present"
				addRepeatedSamples(&w)
			case "single", "shared_cdn":
			case "multi_browser":
				w.TLSStacks = []string{"chrome", "firefox", "app"}
			case "ttl_only", "roaming":
				w.TTLPaths = []string{"out:64:1", "out:64:2"}
				want = "insufficient"
			case "ua_only":
				w.UAOS = []string{"Android", "Windows"}
				want = "insufficient"
			case "random_mac":
				w.DHCPProfiles = []string{"Android", "Windows"}
				want = "insufficient"
			case "missing_scope":
				c.Sources = nil
				want = "insufficient"
			case "untrusted_source":
				w.Sources = []string{"self-verified"}
				want = "insufficient"
			case "stale":
				w.LastObservedAt = now.Add(-time.Hour)
				want = "insufficient"
			case "partial":
				w.Complete = false
				want = "insufficient"
			case "identity_conflict":
				other := session
				other.ID = "s2"
				other.AccountID = "b"
				ss = append(ss, other)
				want = "insufficient"
			case "ip_rebound":
				ss[0].EndedAt = now.Add(-30 * time.Second)
				other := session
				other.ID = "s2"
				other.AccountID = "b"
				other.StartedAt = ss[0].EndedAt
				ss = append(ss, other)
				want = "insufficient"
			case "evidence_conflict":
				w.Conflicts = []string{"duplicate_event_changed"}
				want = "insufficient"
			}
			result := Evaluate(w, c, ss, now, 10*time.Minute)
			if result.State != want {
				t.Fatalf("state=%s want=%s reasons=%v", result.State, want, result.Reasons)
			}
			if name == "hotspot" && (result.DeviceLowerBound != 1 || result.AccountID != "a" || result.Confidence <= 0 || len(result.SignalGroups) < 3) {
				t.Fatal("fabricated downstream device count or missing basis", result)
			}
			if name == "hotspot_unknown_device" && (result.QuantityKnown || result.DeviceLowerBound != 0) {
				t.Fatal("invented a device identity", result)
			}
			if name == "ip_rebound" && result.AccountID != "" {
				t.Fatal("IP ownership retroactively assigned", result)
			}
		})
	}
}
func TestSharedAccessInputKeepsUnknownAndObservationGate(t *testing.T) {
	now := time.Now().UTC()
	present := Result{ID: "shared-1", State: "basis_present", AccountID: "a", ObservedAt: now, EvidenceIDs: []string{"shared-1"}}
	if in := Input("a", []Result{present}, "observe"); !in.Known || !in.Violated {
		t.Fatal(in)
	}
	if in := Input("a", []Result{present}, "manual"); !in.Known || !in.Violated {
		t.Fatal("manual evidence unavailable", in)
	}
	for _, mode := range []string{"automatic", "invalid"} {
		if in := Input("a", []Result{present}, mode); in.Known {
			t.Fatal("observation gate bypassed", mode, in)
		}
	}
	if in := Input("a", nil, "observe"); in.Known || in.Violated {
		t.Fatal("missing evidence became recovery", in)
	}
	negative := present
	negative.State = "not_matched"
	if in := Input("a", []Result{negative}, "observe"); !in.Known || in.Violated {
		t.Fatal(in)
	}
}

func TestSharedWindowCannotCombineSequentialLoginsOfSameAccount(t *testing.T) {
	now := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	cfg := Config{Version: "test", Sources: []Source{{SensorID: "capture", Source: "dpi", CampusID: "campus", AccessDomain: "nas"}}}
	first := policy.Session{ID: "old", AccountID: "a", IP: "192.0.2.1", Source: "auth", CampusID: "campus", AccessDomain: "nas", StartedAt: now.Add(-time.Hour), EndedAt: now.Add(-30 * time.Second), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}
	next := first
	next.ID = "new"
	next.StartedAt = first.EndedAt
	next.EndedAt = time.Time{}
	w := Window{ID: "shared", RuleVersion: RuleVersion, IP: first.IP, SensorID: "capture", CampusID: "campus", AccessDomain: "nas", Sources: []string{"dpi"}, From: now.Add(-time.Minute), To: now, LastObservedAt: now, Complete: true, EventIDs: []string{"e"}, UAOS: []string{"Android", "Windows"}, TTLPaths: []string{"out:64:1", "out:128:1"}, DHCPProfiles: []string{"phone", "desktop"}}
	r := Evaluate(w, cfg, []policy.Session{first, next}, now, 10*time.Minute)
	if r.State != "insufficient" || r.AccountID != "" {
		t.Fatalf("sequential devices combined: %+v", r)
	}
}

func addRepeatedSamples(w *Window) {
	for family, values := range map[string][]string{"ua_os": w.UAOS, "ttl_path": w.TTLPaths, "tls_stack": w.TLSStacks, "dhcp_stack": w.DHCPProfiles} {
		for _, value := range values {
			for _, at := range []time.Time{w.From, w.From.Add(time.Second), w.To} {
				w.ObserveFeature(family, value, at)
			}
		}
	}
}
