package store

import (
	"proxy-sentinel/internal/evidence"
	"testing"
	"time"
)

func TestSharedDeviceArchiveRetainsIdentityAfterHoliday(t *testing.T) {
	now := time.Now().UTC()
	old := evidence.RouterEvidence{EvidenceID: "dhcp-role", AssessmentID: "router", EndpointID: "mac:00:11:22:33:44:55", IP: "192.0.2.22", MAC: "00:11:22:33:44:55", Brand: "ZTE", Model: "SR7410-20", Role: "router", SourceFamily: "dhcp", Score: 60, LastSeen: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano), ExpiresAt: now.Add(-6 * 24 * time.Hour).Format(time.RFC3339Nano)}
	profiles := buildSharedDeviceProfiles([]evidence.RouterEvidence{old}, now)
	if len(profiles) != 1 || profiles[0].Role != "router" || profiles[0].IdentityCurrent || profiles[0].Model != "SR7410-20" {
		t.Fatalf("holiday identity disappeared or became current: %+v", profiles)
	}
	if profiles[0].CurrentShared {
		t.Fatal("router identity promoted to sharing")
	}
}

func TestSharedDeviceArchiveVendorAndDerivedFactsCannotConfirmRole(t *testing.T) {
	now := time.Now().UTC()
	facts := []evidence.RouterEvidence{
		{EvidenceID: "cloud", AssessmentID: "vendor", IP: "192.0.2.63", MAC: "00:11:22:33:44:63", Brand: "TP-Link", Role: "unknown", SourceFamily: "tls_management", Score: 10, BrandReferenceOnly: true, BrandAttribution: true, LastSeen: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
		{EvidenceID: "circular", AssessmentID: "derived", IP: "192.0.2.82", Role: "router", SourceFamily: "shared_gateway_behavior", Score: 85, LastSeen: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
	}
	profiles := buildSharedDeviceProfiles(facts, now)
	if len(profiles) != 1 || profiles[0].Role != "" || profiles[0].IdentityState != "reference" {
		t.Fatalf("vendor or circular fact became device identity: %+v", profiles)
	}
}

func TestSharedDeviceArchiveKeepsMACIdentitySeparateAcrossIPReuse(t *testing.T) {
	now := time.Now().UTC()
	facts := []evidence.RouterEvidence{}
	for _, mac := range []string{"00:11:22:33:44:01", "00:11:22:33:44:02"} {
		facts = append(facts, evidence.RouterEvidence{EvidenceID: mac, AssessmentID: mac, IP: "192.0.2.22", MAC: mac, Brand: "Example", Model: mac, Role: "router", SourceFamily: "dhcp", Score: 60, LastSeen: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)})
	}
	profiles := buildSharedDeviceProfiles(facts, now)
	if len(profiles) != 2 || profiles[0].ProfileID == profiles[1].ProfileID {
		t.Fatalf("IP reuse merged hardware identity: %+v", profiles)
	}
}

func TestSharedDeviceArchiveKeepsLowScoreRouterAsAuthenticationCandidateOnly(t *testing.T) {
	now := time.Now().UTC()
	fact := evidence.RouterEvidence{EvidenceID: "ssdp-router", AssessmentID: "candidate", EndpointID: "mac:00:11:22:33:44:77", IP: "192.168.1.1", MAC: "00:11:22:33:44:77", Role: "router", SourceFamily: "ssdp_upnp", Score: 20, Explanation: "UPnP gateway advertisement", LastSeen: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	if profiles := buildSharedDeviceProfiles([]evidence.RouterEvidence{fact}, now); len(profiles) != 0 {
		t.Fatalf("low-score router became durable identity: %+v", profiles)
	}
	candidates := buildAuthBackedRouterCandidates([]evidence.RouterEvidence{fact}, now)
	if len(candidates) != 1 || candidates[0].Role != "router" || candidates[0].IdentityState != "reference" || candidates[0].IdentityCurrent {
		t.Fatalf("authentication candidate not preserved as a weak lead: %+v", candidates)
	}
	conflict := fact
	conflict.EvidenceID = "conflict"
	conflict.Conflict = true
	if candidates = buildAuthBackedRouterCandidates([]evidence.RouterEvidence{conflict}, now); len(candidates) != 0 {
		t.Fatalf("conflicting router observation became authentication candidate: %+v", candidates)
	}
}

func TestSharedBehaviorHistoricalQueryDoesNotReviveOldConfirmation(t *testing.T) {
	where, _, err := sharedBehaviorWhere(SharedBehaviorQuery{View: "history"})
	if err != nil {
		t.Fatal(err)
	}
	if where == "" {
		t.Fatal("historical view has no query")
	}
	_, _, err = sharedBehaviorWhere(SharedBehaviorQuery{View: "everything"})
	if err == nil {
		t.Fatal("invalid view accepted")
	}
}
