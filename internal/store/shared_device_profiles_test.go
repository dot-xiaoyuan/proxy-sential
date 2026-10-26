package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
)

func profileAssessment(now time.Time, status string, expiresIn time.Duration) *evidence.RouterAssessment {
	return &evidence.RouterAssessment{AssessmentID: "router-" + status, IP: "192.0.2.22", MAC: "00:11:22:33:44:55", Brand: "ZTE", Model: "SR7410-20", Role: "router", Status: status, Confidence: 70,
		FirstSeen: now.Add(-time.Hour).Format(time.RFC3339Nano), LastSeen: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(expiresIn).Format(time.RFC3339Nano),
		Evidence: []evidence.RouterEvidence{{Explanation: "OUI 厂商参考", Score: 5}, {Explanation: "DHCP 型号匹配", Score: 60}}}
}

func applyProfile(now time.Time, profile SharedDeviceProfile, sources sharedProfileSource) SharedDeviceProfile {
	profile, _, _, _ = applySharedProfileSources(profile, sources, sharedDeviceProfileJob{}, now, now, now)
	return profile
}

func TestSharedProfileCandidateStaysCurrentWithRouterStatus(t *testing.T) {
	now := time.Now().UTC()
	profile := applyProfile(now, SharedDeviceProfile{}, sharedProfileSource{Assessment: profileAssessment(now, "candidate", time.Hour)})
	if profile.IdentityState != "supported" || !profile.IdentityCurrent || profile.RouterStatus != "candidate" || profile.RoleSource != "assessment" {
		t.Fatalf("current candidate was relabelled as history: %+v", profile)
	}
	if profile.IdentityBasis != "DHCP 型号匹配" {
		t.Fatalf("identity basis is not the strongest evidence: %q", profile.IdentityBasis)
	}
}

func TestSharedProfileExpiredIdentityIsHistoricalAfterHoliday(t *testing.T) {
	now := time.Now().UTC()
	profile := applyProfile(now, SharedDeviceProfile{}, sharedProfileSource{Assessment: profileAssessment(now, "likely", -6*24*time.Hour)})
	if profile.IdentityState != "historical" || profile.IdentityCurrent || profile.Role != "router" || profile.Model != "SR7410-20" || profile.RouterStatus != "likely" {
		t.Fatalf("holiday identity disappeared or stayed current: %+v", profile)
	}
	if profile.CurrentShared {
		t.Fatal("router identity promoted to sharing")
	}
}

func TestSharedProfileBrandReferenceIsNotDisplayedAsDeviceName(t *testing.T) {
	now := time.Now().UTC()
	vendor := profileAssessment(now, "candidate", time.Hour)
	vendor.Model, vendor.BrandReferenceOnly = "", true
	stale := SharedDeviceProfile{DisplayName: "ZTE", Brand: "ZTE"}
	profile := applyProfile(now, stale, sharedProfileSource{Assessment: vendor})
	if profile.DisplayName != "192.0.2.22" || !profile.BrandReferenceOnly || profile.Brand != "ZTE" {
		t.Fatalf("vendor reference became device name: %+v", profile)
	}
}

func TestSharedProfileDiscoveryRoleIsHintAndNeverCurrent(t *testing.T) {
	now := time.Now().UTC()
	hint := &discovery.Observation{IP: "192.168.1.1", MAC: "00:11:22:33:44:77", DeviceType: "gateway", Explanation: "SSDP 设备自报信息，不确认整机类型", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
	profile := applyProfile(now, SharedDeviceProfile{IdentityState: "supported", IdentityCurrent: true, Role: "gateway"}, sharedProfileSource{Discovery: hint})
	if profile.Role != "gateway" || profile.RoleSource != "discovery_hint" || profile.IdentityState != "reference" || profile.IdentityCurrent {
		t.Fatalf("self-reported discovery role became current identity: %+v", profile)
	}
	shared := &sharedaccess.BehaviorAssessment{ObservationID: "window", FirstSeen: now.Add(-time.Hour), LastSeen: now, ExpiresAt: now.Add(time.Hour), WindowEnd: now}
	inferred := applyProfile(now, SharedDeviceProfile{}, sharedProfileSource{Shared: shared})
	if inferred.Role != "shared_gateway" || inferred.RoleSource != "inferred_shared_gateway" || !inferred.CurrentShared {
		t.Fatalf("sharing window role not marked as inferred: %+v", inferred)
	}
}

func TestSharedProfileAddressOnlyDiscoveryDoesNotQualify(t *testing.T) {
	addressOnly := discovery.Observation{IP: "192.168.1.1", DeviceType: "gateway"}
	if qualifyingSharedProfileSource(sharedProfileSource{Discovery: &addressOnly}) {
		t.Fatal("SSDP announcement without hardware identity created a profile")
	}
	withMAC := addressOnly
	withMAC.MAC = "00:11:22:33:44:77"
	if !qualifyingSharedProfileSource(sharedProfileSource{Discovery: &withMAC}) {
		t.Fatal("discovery record with hardware identity was rejected")
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

func TestSharedProfileClaimKeepsLeaseAdvisoryUntilResultCommit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL synchronous_commit = off`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`WITH picked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"subject_key", "sensor_id", "campus_id", "endpoint_id", "mac", "ip", "vlan", "observed_at", "dirty_generation", "attempts", "lease_owner"}).
			AddRow("subject-a", "sensor-a", "campus-a", "endpoint-a", "", "192.0.2.1", "", now, int64(7), 0, "worker:token"))
	mock.ExpectCommit()
	job, found, err := (&DBStore{pg: &PostgresStore{db: db}}).claimSharedDeviceProfileJob(context.Background(), "worker")
	if err != nil || !found || job.SubjectKey != "subject-a" || job.DirtyGeneration != 7 {
		t.Fatalf("claim failed: %+v found=%t err=%v", job, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
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

func TestSharedDeviceProfileAccountFilterBeforePagination(t *testing.T) {
	for _, has := range []bool{true, false} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		mock.ExpectQuery(`(?s)filtered AS NOT MATERIALIZED.*btrim\(coalesce\(p.latest_account_id,''\)\)<>''.*page AS`).WithArgs("sensor", has, 20, 40).WillReturnRows(sqlmock.NewRows([]string{"items", "total", "last_success_at", "last_error", "materialized_at", "pending_jobs", "oldest_pending_at", "checked_at"}).AddRow([]byte("[]"), 40, now, "", now, 0, nil, now))
		_, err = (&PostgresStore{db: db, sensorID: "sensor"}).ListSharedDeviceProfiles(context.Background(), SharedDeviceProfileQuery{HasAccount: &has, Limit: 20, Cursor: 40})
		if err != nil {
			t.Fatal(err)
		}
		if err = mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}
