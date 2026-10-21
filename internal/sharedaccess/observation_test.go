package sharedaccess

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestRecordedSharingRequiresAnchorAndMappedEventIdentity(t *testing.T) {
	now := time.Date(2026, 10, 16, 0, 10, 0, 0, time.UTC)
	w := Window{ID: "w", RuleVersion: RuleVersion, SensorID: "mirror", CampusID: "ncu", AccessDomain: "mirror-domain", IP: "192.0.2.1", Sources: []string{"handshake-sidecar"}, From: now.Add(-time.Minute), To: now, LastObservedAt: now, Complete: true, CoverageVerified: true, EventIDs: []string{"a", "b", "c"}, Records: []RecordRef{{EventID: "a", Source: "handshake-sidecar", InstanceID: "one"}}, StrongAnchor: "ieee1905_association", DeviceLowerBound: 2, AssociatedClients: []string{"one", "two"}}
	cfg := Config{Version: "v1", FreshnessSeconds: 180, Sources: []Source{{SensorID: "mirror", Source: "handshake-sidecar", CampusID: "ncu", AccessDomain: "mirror-domain"}}, IdentityMappings: []IdentityMapping{{SensorID: "mirror", CampusID: "ncu", AccessDomain: "mirror-domain", Source: "auth", IdentitySensorID: "auth-sensor", IdentityCampusID: "ncu", IdentityAccessDomain: "campus-auth", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}}}
	ss := []policy.Session{{ID: "s", AccountID: "account", IP: w.IP, Source: "auth", SensorID: "auth-sensor", CampusID: "ncu", AccessDomain: "campus-auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-2 * time.Minute), now}, HeartbeatSeconds: 60}}
	r := EvaluateObservation(w, cfg, ss, now)
	if r.State != "basis_present" || r.AccountID != "account" || r.DeviceLowerBound != 2 {
		t.Fatalf("%+v", r)
	}
	for _, mode := range []string{"owner_changed", "generation_changed", "multiple_accounts", "source_interrupted", "source_gap", "source_recovered"} {
		t.Run(mode, func(t *testing.T) {
			input := append([]policy.Session{}, ss...)
			window := w
			switch mode {
			case "owner_changed", "generation_changed":
				input[0].EndedAt = w.From.Add(30 * time.Second)
				next := ss[0]
				next.ID, next.StartedAt = "new-generation", input[0].EndedAt
				if mode == "owner_changed" {
					next.AccountID = "next-account"
				}
				input = append(input, next)
			case "multiple_accounts":
				next := ss[0]
				next.AccountID, next.ID = "other-account", "other-session"
				input = append(input, next)
			case "source_interrupted":
				input[0].IdentityIssue = "identity_source_interrupted"
			case "source_gap", "source_recovered":
				input[0].SourceCoverage = []policy.IdentityCoverage{{From: w.From.Add(-time.Minute), To: w.From.Add(20 * time.Second)}, {From: w.From.Add(40 * time.Second), To: now.Add(time.Minute)}}
				if mode == "source_recovered" {
					window.From = now.Add(-10 * time.Second)
				}
			}
			got := EvaluateObservation(window, cfg, input, now)
			if mode == "source_recovered" {
				if got.State != "basis_present" || got.AccountID != "account" {
					t.Fatalf("%+v", got)
				}
			} else if got.State != "insufficient" {
				t.Fatalf("%+v", got)
			}
		})
	}
	w.StrongAnchor = ""
	w.AssociatedClients = nil
	if r = EvaluateObservation(w, cfg, ss, now); r.State == "basis_present" {
		t.Fatal("candidate triggered")
	}
	w.StrongAnchor = "ieee1905_association"
	w.AssociatedClients = []string{"one", "two"}
	ss[0].AccessDomain = "other"
	if r = EvaluateObservation(w, cfg, ss, now); r.State == "basis_present" {
		t.Fatal("borrowed other authority")
	}
	ss[0].AccessDomain = "campus-auth"
	cfg.IdentityMappings[0].ValidFrom = now.Add(-30 * time.Second)
	if r = EvaluateObservation(w, cfg, ss, now); r.State == "basis_present" {
		t.Fatal("retroactive mapping")
	}
}

func TestCoverageDoesNotBorrowOtherIPOrInstance(t *testing.T) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	w := Window{SensorID: "s", CampusID: "c", AccessDomain: "d", IP: "192.0.2.1", From: now.Add(-time.Minute), To: now, Records: []RecordRef{{Source: "handshake-sidecar", InstanceID: "one"}}}
	cfg := Config{Sources: []Source{{SensorID: "s", CampusID: "c", AccessDomain: "d", Source: "handshake-sidecar"}}}
	c := CoverageV2{SchemaVersion: "capture-coverage/v2", From: w.From, To: w.To, KernelStatsKnown: true}
	global := c
	global.Omitted = 10
	local := CoverageFact{Source: "handshake-sidecar", Instance: "one", IP: w.IP, Coverage: c}
	facts := []CoverageFact{{Source: "handshake-sidecar", Instance: "one", Coverage: global}, local}
	if reasons := VerifyCoverage(w, cfg, facts); len(reasons) != 0 {
		t.Fatalf("another IP's trimming rejected complete local capture: %v", reasons)
	}
	facts[1].IP = "192.0.2.2"
	if len(VerifyCoverage(w, cfg, facts)) == 0 {
		t.Fatal("borrowed other IP coverage")
	}
	facts[1] = local
	facts[0].Coverage.Dropped = 1
	if len(VerifyCoverage(w, cfg, facts)) == 0 {
		t.Fatal("ignored unlocated kernel drops")
	}
	facts = []CoverageFact{local}
	facts[0].Instance = "two"
	if len(VerifyCoverage(w, cfg, facts)) == 0 {
		t.Fatal("borrowed other instance")
	}
	facts[0] = local
	facts[0].Coverage.SchemaVersion = "v1"
	if len(VerifyCoverage(w, cfg, facts)) == 0 {
		t.Fatal("legacy coverage auto-upgraded")
	}
}

func TestHardwareFeaturesDoNotCountBrowserFormattingAsDevices(t *testing.T) {
	for _, pair := range [][2]string{
		{"Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S9280 Build/TEST)", "Mozilla/5.0 (Linux; Android 14; sm-s9280 Build/TEST)"},
		{"Mozilla/5.0 (Linux; Android 13; HUAWEI VOG-L29 Build/TEST)", "Mozilla/5.0 (Linux; Android 13; VOG-L29 Build/TEST)"},
	} {
		a, b := HandshakeFeatures("user_agent", pair[0]), HandshakeFeatures("user_agent", pair[1])
		if a["device_model"] == "" || a["device_model"] != b["device_model"] {
			t.Fatalf("same model differs by browser formatting: %v %v", a, b)
		}
	}
	for _, ua := range []string{"Mozilla/5.0 (Linux; Android 10; K Build/TEST)", "Mozilla/5.0 (Linux; Android 14; generic_x86 Build/TEST)", "Mozilla/5.0 (Linux; Android 14 Build/TEST)"} {
		if HandshakeFeatures("user_agent", ua)["device_model"] != "" {
			t.Fatalf("generic UA became hardware: %s", ua)
		}
	}
	if HandshakeFeatures("user_agent", "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/TEST)")["device_model"] == "" {
		t.Fatal("explicit Pixel model lost")
	}
}

func TestRouterSharingDecisionRecordOnly(t *testing.T) {
	now := time.Now().UTC()
	cfg := Config{FreshnessSeconds: 180}
	w := Window{ID: "proof", LastObservedAt: now, Complete: true, CoverageVerified: true, StrongAnchor: "ieee1905_association", DeviceLowerBound: 2}
	r := Result{State: "basis_present", AccountID: "account", SessionGeneration: "session"}
	got := NewObservationDecision(w, r, cfg, now)
	if got.Result != "matched" || got.ExecutionID == "" || !got.Violated || !got.Known || got.DeliveryStatus != "record_only" || got.Mode != "manual" {
		t.Fatalf("record_only decision incorrect: %+v", got)
	}
	r.State = "insufficient"
	got = NewObservationDecision(w, r, cfg, now)
	if got.Result != "insufficient" || got.ExecutionID != "" || got.Violated || got.Known {
		t.Fatalf("insufficient should not become matched: %+v", got)
	}
}
