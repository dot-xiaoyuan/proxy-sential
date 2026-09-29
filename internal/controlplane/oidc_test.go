package controlplane

import "testing"

func TestRoleForGroupsUsesHighestMappedRole(t *testing.T) {
	got := roleForGroups([]string{"students", "security-operators"}, map[string]string{"students": "viewer", "security-operators": "operator"}, "viewer")
	if got != "operator" {
		t.Fatalf("role=%q", got)
	}
}

func TestParseOIDCRoleMappingRejectsUnknownRole(t *testing.T) {
	if _, err := ParseOIDCRoleMapping(`{"staff":"root"}`); err == nil {
		t.Fatal("expected invalid role error")
	}
}
