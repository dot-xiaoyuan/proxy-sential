package sharedaccess

import (
	"testing"
	"time"
)

func repeatedBehaviorWindow(now time.Time, families map[string][]string) Window {
	w := Window{
		ID: "window", RuleVersion: RuleVersion, SensorID: "sensor", CampusID: "campus", AccessDomain: "nas",
		IP: "192.0.2.10", From: now.Add(-10 * time.Minute), To: now, LastObservedAt: now,
		Complete: true, CoverageVerified: true, Samples: map[string]map[string]FeatureSample{}, EventIDs: []string{"event"},
	}
	for family, values := range families {
		w.Samples[family] = map[string]FeatureSample{}
		for _, value := range values {
			w.Samples[family][value] = FeatureSample{Count: 3, Buckets: []int64{now.Add(-time.Minute).Unix() / 5, now.Add(-30*time.Second).Unix() / 5}}
		}
	}
	w.UAOS = families["ua_os"]
	w.TTLPaths = families["ttl_path"]
	w.TCPStacks = families["tcp_stack"]
	w.TLSStacks = families["tls_stack"]
	w.DHCPProfiles = families["dhcp_stack"]
	return w
}

func TestAssessBehaviorRequiresIndependentRepeatedSignals(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{"ua_os": {"Android", "Windows"}})
	if _, present := AssessBehavior("one", "", w, BehaviorRouterContext{}); present {
		t.Fatal("single signal family became a shared behavior observation")
	}
	w.TTLPaths = []string{"initial=64,hops=1", "initial=128,hops=1"}
	w.Samples["ttl_path"] = map[string]FeatureSample{}
	for _, value := range w.TTLPaths {
		w.Samples["ttl_path"][value] = FeatureSample{Count: 3, Buckets: []int64{now.Add(-time.Minute).Unix() / 5, now.Add(-30*time.Second).Unix() / 5}}
	}
	item, present := AssessBehavior("two", "endpoint", w, BehaviorRouterContext{})
	if !present || item.Status != "likely" || item.Confidence != 65 {
		t.Fatalf("two repeated independent signals were not retained as likely: %+v present=%t", item, present)
	}
}

func TestAssessBehaviorRejectsTLSAndTCPDiversityFromOneEndpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{
		"tcp_stack": {"mss=1460,ws=8", "mss=1460,ws=9"},
		"tls_stack": {"ja3:browser", "ja3:application"},
	})
	if _, present := AssessBehavior("phone", "endpoint", w, BehaviorRouterContext{}); present {
		t.Fatal("ordinary per-application TLS/TCP diversity became shared gateway behavior")
	}
	w.UAOS = []string{"Android", "Windows"}
	w.Samples["ua_os"] = map[string]FeatureSample{
		"Android": {Count: 3, Buckets: []int64{now.Add(-time.Minute).Unix() / 5, now.Add(-30*time.Second).Unix() / 5}},
		"Windows": {Count: 3, Buckets: []int64{now.Add(-time.Minute).Unix() / 5, now.Add(-30*time.Second).Unix() / 5}},
	}
	if item, present := AssessBehavior("gateway", "endpoint", w, BehaviorRouterContext{}); !present || item.Status != "confirmed" {
		t.Fatalf("cross-OS evidence did not restore the shared gateway result: %+v present=%t", item, present)
	}
}

func TestAssessBehaviorConfirmationAndCoverageGate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{
		"ua_os": {"Android", "Windows"}, "ttl_path": {"initial=64,hops=1", "initial=128,hops=1"}, "tls_stack": {"ja4:a", "ja4:b"},
	})
	item, present := AssessBehavior("three", "endpoint", w, BehaviorRouterContext{})
	if !present || item.Status != "confirmed" || item.Confidence != 95 {
		t.Fatalf("three repeated signal groups should confirm shared behavior: %+v", item)
	}
	two := repeatedBehaviorWindow(now, map[string][]string{
		"ua_os": {"Android", "Windows"}, "ttl_path": {"initial=64,hops=1", "initial=128,hops=1"},
	})
	item, present = AssessBehavior("router", "endpoint", two, BehaviorRouterContext{AssessmentID: "router-1", Role: "router", Status: "likely", Confidence: 70})
	if !present || item.Status != "confirmed" || item.Confidence != 85 {
		t.Fatalf("two signals plus a strong router identity should confirm: %+v", item)
	}
	two.CoverageVerified = false
	two.Complete = false
	item, present = AssessBehavior("partial", "endpoint", two, BehaviorRouterContext{AssessmentID: "router-1", Role: "router", Status: "confirmed", Confidence: 90})
	if !present || item.Status != "candidate" || item.Confidence != 59 || item.CoverageState != "partial" {
		t.Fatalf("partial capture bypassed the confirmation gate: %+v", item)
	}
}

func TestAssessBehaviorConfirmsWithRepeatedTCPStackEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{
		"ua_os":    {"Android", "Windows"},
		"ttl_path": {"initial=64,hops=1", "initial=128,hops=1"},
		"tcp_stack": {
			"mss=1460,ws=7,sack=true,ts=true,df=true,opt=2-4-8-1-3",
			"mss=1460,ws=8,sack=true,ts=true,df=true,opt=2-4-8-1-3",
		},
	})
	item, present := AssessBehavior("tcp", "endpoint", w, BehaviorRouterContext{})
	if !present || item.Status != "confirmed" || item.Confidence != 95 {
		t.Fatalf("three repeated signal groups including TCP should confirm shared behavior: %+v", item)
	}
}

func TestAssessBehaviorRejectsNonCoexistingDiversity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{
		"ua_os": {"Android", "Windows"}, "ttl_path": {"initial=64,hops=1", "initial=128,hops=1"},
	})
	w.Samples["ua_os"]["Windows"] = FeatureSample{Count: 3, Buckets: []int64{now.Add(-9*time.Minute).Unix() / 5, now.Add(-8*time.Minute).Unix() / 5}}
	if _, present := AssessBehavior("separate", "", w, BehaviorRouterContext{}); present {
		t.Fatal("diversity without repeated temporal coexistence became shared behavior")
	}
}

func TestAssessBehaviorIgnoresNoisyThirdValueWhenARepeatedPairCoexists(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{
		"ua_os":    {"Android", "Windows"},
		"ttl_path": {"initial=64,hops=1", "initial=128,hops=1"},
	})
	w.TTLPaths = append(w.TTLPaths, "initial=255,hops=1")
	w.Samples["ttl_path"]["initial=255,hops=1"] = FeatureSample{Count: 1, Buckets: []int64{now.Add(-10*time.Second).Unix() / 5}}
	item, present := AssessBehavior("noisy", "", w, BehaviorRouterContext{})
	if !present || item.Status != "likely" || item.Confidence != 65 {
		t.Fatalf("a noisy third value suppressed the valid repeated pair: %+v present=%t", item, present)
	}
}
