package store

import "testing"

func TestAccountTagVersionTracksEvidenceAndRuleChanges(t *testing.T) {
	base := AccountTagAssessment{
		AccountID:     "student-1",
		TagType:       "router",
		EvidenceLevel: "likely",
		SourceType:    "router_observation",
		EndpointIDs:   []string{"endpoint-1"},
		EvidenceIDs:   []string{"router-1"},
		RuleVersion:   "router-v1",
		FirstSeen:     "2026-10-14T01:00:00Z",
		LastSeen:      "2026-10-14T02:00:00Z",
		ValidUntil:    "2026-10-15T02:00:00Z",
	}
	if first, second := accountTagVersion(base), accountTagVersion(base); first != second {
		t.Fatalf("unchanged assessment version is unstable: %q != %q", first, second)
	}
	refreshed := base
	refreshed.FirstSeen = "2026-10-14T01:01:00Z"
	refreshed.LastSeen = "2026-10-14T02:01:00Z"
	refreshed.ValidUntil = "2026-10-15T02:01:00Z"
	if accountTagVersion(base) != accountTagVersion(refreshed) {
		t.Fatal("observation timestamps must not create new assessment history")
	}
	changed := base
	changed.RuleVersion = "router-v2"
	if accountTagVersion(base) == accountTagVersion(changed) {
		t.Fatal("rule version change must create a new assessment version")
	}
	changed = base
	changed.EvidenceIDs = []string{"router-2"}
	if accountTagVersion(base) == accountTagVersion(changed) {
		t.Fatal("independent evidence must create a new assessment version")
	}
	changed = base
	changed.Reason = "路由身份依据已变化"
	if accountTagVersion(base) == accountTagVersion(changed) {
		t.Fatal("a changed conclusion must create a new assessment version")
	}
}
