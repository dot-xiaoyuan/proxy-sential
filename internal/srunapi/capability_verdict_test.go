package srunapi

import (
	"reflect"
	"testing"
)

func TestBuildInventoryVerdictProvenRequiresCompleteAndFields(t *testing.T) {
	verdict := BuildInventoryVerdict([]EquipmentCapabilities{{
		Shape:       "array",
		RecordCount: 3,
		Fields:      []string{"rad_online_id", "session_id", "user_name", "add_time", "ip", "user_mac", "nas_ip"},
		Complete:    true,
	}}, nil)
	if verdict.Completeness != "proven" {
		t.Fatalf("expected proven verdict, got %+v", verdict)
	}
	if len(verdict.Blockers) != 0 || len(verdict.MissingRequiredFields) != 0 {
		t.Fatalf("proven verdict must have no blockers, got %+v", verdict)
	}
	if !reflect.DeepEqual(verdict.PresentOptionalFields, []string{"nas_ip", "user_mac"}) {
		t.Fatalf("unexpected optional fields: %+v", verdict.PresentOptionalFields)
	}
}

func TestBuildInventoryVerdictNativeEndpointsStayUnproven(t *testing.T) {
	// The legacy management endpoints report Complete=false even when they return
	// every required field; completeness must never be inferred from fields alone.
	verdict := BuildInventoryVerdict([]EquipmentCapabilities{{
		Shape:       "array",
		RecordCount: 81,
		Fields:      []string{"rad_online_id", "session_id", "user_name", "add_time", "ip", "ipv6"},
		Complete:    false,
		Blocker:     "inventory_completeness_unproven",
	}}, nil)
	if verdict.Completeness != "unproven" {
		t.Fatalf("expected unproven verdict, got %+v", verdict)
	}
	if !containsString(verdict.Blockers, "inventory_completeness_unproven") {
		t.Fatalf("expected completeness blocker, got %+v", verdict.Blockers)
	}
	if len(verdict.EndpointBlockers) == 0 {
		t.Fatalf("expected endpoint blockers to be surfaced: %+v", verdict)
	}
}

func TestBuildInventoryVerdictReportsMissingFields(t *testing.T) {
	verdict := BuildInventoryVerdict([]EquipmentCapabilities{{
		Shape:    "array",
		Fields:   []string{"user_name", "group_id"},
		Complete: false,
	}}, nil)
	// user_name is the only observable required field; the rest are missing and
	// no usable address column is present.
	want := []string{"add_time", "ip|ipv6|ip6", "rad_online_id", "session_id"}
	if !reflect.DeepEqual(verdict.MissingRequiredFields, want) {
		t.Fatalf("missing fields = %+v, want %+v", verdict.MissingRequiredFields, want)
	}
	if !containsString(verdict.Blockers, "inventory_address_field_missing") {
		t.Fatalf("expected address blocker, got %+v", verdict.Blockers)
	}
	if !reflect.DeepEqual(verdict.PresentOptionalFields, []string{"group_id"}) {
		t.Fatalf("unexpected optional fields: %+v", verdict.PresentOptionalFields)
	}
}

func TestBuildInventoryVerdictNormalizesFieldCase(t *testing.T) {
	verdict := BuildInventoryVerdict([]EquipmentCapabilities{{
		Fields:   []string{" RAD_ONLINE_ID ", "Session_ID", "USER_NAME", "Add_Time", "IP"},
		Complete: true,
	}}, nil)
	if verdict.Completeness != "proven" || len(verdict.MissingRequiredFields) != 0 {
		t.Fatalf("field normalization failed: %+v", verdict)
	}
}

func TestBuildInventoryVerdictNoEndpoints(t *testing.T) {
	verdict := BuildInventoryVerdict(nil, nil)
	if verdict.Completeness != "unproven" {
		t.Fatalf("expected unproven verdict, got %+v", verdict)
	}
	if !containsString(verdict.Blockers, "inventory_endpoint_unavailable") {
		t.Fatalf("expected unavailable blocker, got %+v", verdict.Blockers)
	}
	if !reflect.DeepEqual(verdict.MissingRequiredFields, []string{"add_time", "ip|ipv6|ip6", "rad_online_id", "session_id", "user_name"}) {
		t.Fatalf("unexpected missing fields: %+v", verdict.MissingRequiredFields)
	}
}

func TestBuildInventoryVerdictCompleteButMissingFieldIsUnproven(t *testing.T) {
	verdict := BuildInventoryVerdict([]EquipmentCapabilities{{
		Fields:   []string{"rad_online_id", "user_name", "add_time", "ip"},
		Complete: true,
	}}, nil)
	if verdict.Completeness != "unproven" {
		t.Fatalf("missing session_id must keep the verdict unproven: %+v", verdict)
	}
	if !containsString(verdict.Blockers, "inventory_required_fields_missing:session_id") {
		t.Fatalf("expected missing-field blocker, got %+v", verdict.Blockers)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
