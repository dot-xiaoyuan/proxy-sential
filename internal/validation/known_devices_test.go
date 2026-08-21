package validation

import (
	"os"
	"strings"
	"testing"

	"proxy-sentinel/internal/store"
)

func TestAnalyzeKnownDeviceCSVParsesTemplate(t *testing.T) {
	file, err := os.Open("../../examples/known-devices-template.csv")
	if err != nil {
		t.Fatalf("open template: %v", err)
	}
	defer file.Close()

	report, err := AnalyzeKnownDeviceCSV(file)
	if err != nil {
		t.Fatalf("analyze template: %v", err)
	}
	if !report.Valid {
		t.Fatalf("template should be structurally valid, got errors: %+v", report.Errors)
	}
	if report.Coverage.Total < 10 {
		t.Fatalf("expected representative seed rows, got %+v", report.Coverage)
	}
	if report.Coverage.Infrastructure < 4 {
		t.Fatalf("expected infrastructure seed rows, got %+v", report.Coverage)
	}
	if report.Coverage.NATOrRouters < 1 {
		t.Fatalf("expected NAT/router seed row, got %+v", report.Coverage)
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("template should warn until expanded to 30-50 known devices")
	}
}

func TestAnalyzeKnownDeviceCSVRejectsInfrastructureAccountPollution(t *testing.T) {
	csv := `sample_id,expected_endpoint_id,primary_mac,expected_account_id,expected_owner_name,expected_owner_department,expected_device_type,expected_os_family,expected_vendor,expected_ip,expected_access_id,expected_vlan,expected_ap,expected_switch_id,expected_switch_port,expected_role,registration_status,is_infrastructure,is_nat_or_router,expected_hidden_downstream_count,first_seen,last_seen,notes
infra-dns,infra:dns-1,,2026000123,,,dns_server,linux,,10.20.0.53,core-dns,20,,core-sw,Gi1/0/2,server,exempt,true,false,0,2026-07-30T00:00:00Z,2026-07-30T01:00:00Z,invalid account on infrastructure
`
	report, err := AnalyzeKnownDeviceCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("analyze csv: %v", err)
	}
	if report.Valid {
		t.Fatalf("expected invalid report")
	}
	if !containsString(report.Errors, "infrastructure sample should not have expected_account_id") {
		t.Fatalf("expected infrastructure account pollution error, got %+v", report.Errors)
	}
}

func TestAnalyzeKnownDeviceCSVRejectsHiddenDownstreamWithoutRouterFlag(t *testing.T) {
	csv := `sample_id,expected_endpoint_id,primary_mac,expected_account_id,expected_owner_name,expected_owner_department,expected_device_type,expected_os_family,expected_vendor,expected_ip,expected_access_id,expected_vlan,expected_ap,expected_switch_id,expected_switch_port,expected_role,registration_status,is_infrastructure,is_nat_or_router,expected_hidden_downstream_count,first_seen,last_seen,notes
router-1,mac:02:00:00:00:02:01,02:00:00:00:02:01,2026000999,student,dorm,personal_router,routeros,Example,10.20.15.1,Dorm-A-401,108,Dorm-A-AP01,,,endpoint,unregistered,false,false,3,2026-07-30T00:00:00Z,2026-07-30T01:00:00Z,invalid router flag
`
	report, err := AnalyzeKnownDeviceCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("analyze csv: %v", err)
	}
	if report.Valid {
		t.Fatalf("expected invalid report")
	}
	if !containsString(report.Errors, "hidden downstream count requires is_nat_or_router=true") {
		t.Fatalf("expected hidden downstream router flag error, got %+v", report.Errors)
	}
}

func TestCompareKnownDevicesToIdentityStatePassesEndpointAndInfrastructure(t *testing.T) {
	samples := []KnownDeviceSample{
		{
			SampleID:           "student-win-001",
			ExpectedEndpointID: "mac:02:00:00:00:01:01",
			PrimaryMAC:         "02:00:00:00:01:01",
			ExpectedAccountID:  "2026000101",
			ExpectedIP:         "10.20.15.83",
			ExpectedAccessID:   "Dorm-A-401",
			ExpectedAP:         "Dorm-A-AP01",
			ExpectedRole:       "endpoint",
			RegistrationStatus: "registered",
		},
		{
			SampleID:           "dns-001",
			ExpectedEndpointID: "infra:dns-001",
			ExpectedIP:         "10.20.0.53",
			ExpectedRole:       "server",
			RegistrationStatus: "exempt",
			IsInfrastructure:   true,
		},
	}
	state := store.IdentityState{
		Endpoints: []store.EndpointEntity{
			{EndpointID: "mac:02:00:00:00:01:01", PrimaryMAC: "02:00:00:00:01:01", EntityRole: "endpoint"},
		},
		Infrastructure: []store.InfrastructureEntity{
			{EntityID: "infra:dns-001", IP: "10.20.0.53", EntityRole: "server"},
		},
		Sessions: []store.AccountSession{
			{AccountID: "2026000101", EndpointID: "mac:02:00:00:00:01:01", StartedAt: "2026-07-30T08:00:00Z"},
		},
		IPMACHistory: []store.IdentityIPMACHistory{
			{EndpointID: "mac:02:00:00:00:01:01", AccountID: "2026000101", EntityRole: "endpoint", IP: "10.20.15.83", MAC: "02:00:00:00:01:01", FirstSeen: "2026-07-30T08:00:00Z", LastSeen: "2026-07-30T08:00:00Z"},
		},
		AccessHistory: []store.IdentityAccessHistory{
			{EndpointID: "mac:02:00:00:00:01:01", AccountID: "2026000101", EntityRole: "endpoint", AccessID: "Dorm-A-401", AP: "Dorm-A-AP01", FirstSeen: "2026-07-30T08:00:00Z", LastSeen: "2026-07-30T08:00:00Z"},
		},
	}

	report := CompareKnownDevicesToIdentityState(samples, state)
	if !report.Valid || report.Passed != 2 || report.Failed != 0 {
		t.Fatalf("expected comparison to pass, got %+v", report)
	}
}

func TestCompareKnownDevicesToIdentityStateDetectsMissingAccess(t *testing.T) {
	samples := []KnownDeviceSample{
		{
			SampleID:           "student-win-001",
			ExpectedEndpointID: "mac:02:00:00:00:01:01",
			PrimaryMAC:         "02:00:00:00:01:01",
			ExpectedAccountID:  "2026000101",
			ExpectedIP:         "10.20.15.83",
			ExpectedAccessID:   "Dorm-A-401",
			ExpectedAP:         "Dorm-A-AP01",
			ExpectedRole:       "endpoint",
			RegistrationStatus: "registered",
		},
	}
	state := store.IdentityState{
		Endpoints: []store.EndpointEntity{
			{EndpointID: "mac:02:00:00:00:01:01", PrimaryMAC: "02:00:00:00:01:01", EntityRole: "endpoint"},
		},
		Sessions: []store.AccountSession{
			{AccountID: "2026000101", EndpointID: "mac:02:00:00:00:01:01", StartedAt: "2026-07-30T08:00:00Z"},
		},
		IPMACHistory: []store.IdentityIPMACHistory{
			{EndpointID: "mac:02:00:00:00:01:01", AccountID: "2026000101", EntityRole: "endpoint", IP: "10.20.15.83", MAC: "02:00:00:00:01:01", FirstSeen: "2026-07-30T08:00:00Z", LastSeen: "2026-07-30T08:00:00Z"},
		},
	}

	report := CompareKnownDevicesToIdentityState(samples, state)
	if report.Valid || report.Failed != 1 {
		t.Fatalf("expected comparison to fail, got %+v", report)
	}
	if !containsString(report.Results[0].Issues, "expected access_id") {
		t.Fatalf("expected missing access issue, got %+v", report.Results[0].Issues)
	}
}

func TestCompareKnownDevicesToIdentityStateDetectsFalseMerge(t *testing.T) {
	samples := []KnownDeviceSample{
		{SampleID: "device-a", ExpectedEndpointID: "endpoint-shared", PrimaryMAC: "02:00:00:00:03:01", ExpectedRole: "endpoint", RegistrationStatus: "registered"},
		{SampleID: "device-b", ExpectedEndpointID: "endpoint-shared", PrimaryMAC: "02:00:00:00:03:02", ExpectedRole: "endpoint", RegistrationStatus: "registered"},
	}
	state := store.IdentityState{Endpoints: []store.EndpointEntity{
		{EndpointID: "endpoint-shared", PrimaryMAC: "02:00:00:00:03:01", EntityRole: "endpoint"},
	}}

	report := CompareKnownDevicesToIdentityState(samples, state)
	if report.Valid || report.FalseMergeCount != 1 || report.Failed != 2 {
		t.Fatalf("expected one false merge affecting both samples, got %+v", report)
	}
	if !containsString(report.Results[0].Issues, "false merge") || !containsString(report.Results[1].Issues, "false merge") {
		t.Fatalf("expected false merge issue on both samples, got %+v", report.Results)
	}
}

func TestCompareKnownDevicesToIdentityStateDetectsDuplicateCreation(t *testing.T) {
	samples := []KnownDeviceSample{
		{SampleID: "device-a", PrimaryMAC: "02:00:00:00:04:01", ExpectedRole: "endpoint", RegistrationStatus: "registered"},
	}
	state := store.IdentityState{Endpoints: []store.EndpointEntity{
		{EndpointID: "endpoint-a", PrimaryMAC: "02:00:00:00:04:01", EntityRole: "endpoint"},
		{EndpointID: "endpoint-a-duplicate", PrimaryMAC: "02:00:00:00:04:01", EntityRole: "endpoint"},
	}}

	report := CompareKnownDevicesToIdentityState(samples, state)
	if report.Valid || report.DuplicateCreationCount != 1 || report.Failed != 1 {
		t.Fatalf("expected duplicate creation failure, got %+v", report)
	}
	if !containsString(report.Results[0].Issues, "duplicate creation") {
		t.Fatalf("expected duplicate creation issue, got %+v", report.Results[0].Issues)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
