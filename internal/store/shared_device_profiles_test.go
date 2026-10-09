package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"proxy-sentinel/internal/evidence"
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

func TestMaterializedSharedProfileRequiresIndependentNetworkEvidence(t *testing.T) {
	brandOnly := evidence.RouterAssessment{Role: "router", Status: "confirmed", Confidence: 95, BrandReferenceOnly: true}
	if qualifyingSharedProfileSource(sharedProfileSource{Assessment: &brandOnly}) {
		t.Fatal("brand-only attribution admitted a durable router profile")
	}
	independent := evidence.RouterAssessment{Role: "router", Status: "likely", Confidence: 70}
	if !qualifyingSharedProfileSource(sharedProfileSource{Assessment: &independent}) {
		t.Fatal("independent likely router evidence was rejected")
	}
	conflict := independent
	conflict.Ambiguous = true
	if qualifyingSharedProfileSource(sharedProfileSource{Assessment: &conflict}) {
		t.Fatal("ambiguous router evidence admitted a durable profile")
	}
}

func TestSharedProfileHistoryIgnoresMaterializerHeartbeatOnly(t *testing.T) {
	old := SharedDeviceProfile{ProfileID: "profile", Role: "router", MaterializedAt: time.Now().Add(-time.Minute)}
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	current := old
	current.MaterializedAt = time.Now()
	if sharedProfileProjectionChanged(raw, current) {
		t.Fatal("materialized timestamp alone produced a history transition")
	}
	current.LatestAccountID = "new-account"
	if !sharedProfileProjectionChanged(raw, current) {
		t.Fatal("account change did not produce a history transition")
	}
}

func TestSharedDeviceProfileListUsesOnePostgresSnapshotQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery(`WITH runtime AS`).WithArgs("sensor-one-query", 20, 0).WillReturnRows(sqlmock.NewRows([]string{
		"items", "total", "last_success_at", "last_error", "materialized_at", "pending_jobs", "oldest_pending_at", "checked_at",
	}).AddRow([]byte("[]"), 0, now, "", now, 0, nil, now))
	page, err := (&PostgresStore{db: db, sensorID: "sensor-one-query"}).ListSharedDeviceProfiles(context.Background(), SharedDeviceProfileQuery{})
	if err != nil || len(page.Items) != 0 || page.Page.Total != 0 || page.FreshnessState != "fresh" {
		t.Fatalf("single snapshot list query failed: %+v %v", page, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
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
