package appdomain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReleaseIndexUsesPublicationTime(t *testing.T) {
	releases := []Release{{Version: "2026.09.09-pilot1", CreatedAt: "2026-09-09T08:30:00Z", OrderingBasis: "created_at_fallback", SHA256: strings.Repeat("a", 64), Size: 100, RuleCount: 61, ApplicationCount: 6}, {Version: "2026.09.09-legacy-ai1", CreatedAt: "2026-09-09T09:42:50Z", OrderingBasis: "created_at_fallback", SHA256: strings.Repeat("b", 64), Size: 200, RuleCount: 90, ApplicationCount: 31}}
	marshal := func(latest string) []byte {
		raw, _ := json.Marshal(map[string]any{"success": true, "data": map[string]any{"latest_version": latest, "releases": releases}})
		return raw
	}
	r, err := selectRelease(marshal("2026.09.09-legacy-ai1"))
	if err != nil || r.Version != "2026.09.09-legacy-ai1" {
		t.Fatalf("wrong latest %+v %v", r, err)
	}
	if _, err = selectRelease(marshal("2026.09.09-pilot1")); err == nil {
		t.Fatal("accepted stale latest metadata")
	}
	releases[0].PublishedAt = "2026-09-10T00:00:00Z"
	releases[0].OrderingBasis = "published_at"
	if _, err = selectRelease(marshal("2026.09.09-pilot1")); err != nil {
		t.Fatal(err)
	}
	releases[1].CreatedAt = "invalid"
	if _, err = selectRelease(marshal("2026.09.09-pilot1")); err == nil {
		t.Fatal("silently skipped invalid old release")
	}
}
func TestReleaseIndexRejectsEmpty(t *testing.T) {
	for _, raw := range []string{`{"success":true,"data":{"latest_version":"","releases":[]}}`, `{"success":false}`, `{"success":true,"data":["v1"]}`} {
		if _, err := selectRelease([]byte(raw)); err == nil {
			t.Fatal("invalid/empty index accepted")
		}
	}
}

func TestReleaseIndexRejectsDuplicateVersions(t *testing.T) {
	r := Release{Version: "v1", CreatedAt: "2026-09-10T00:00:00Z", OrderingBasis: "created_at_fallback", SHA256: strings.Repeat("a", 64), Size: 100, RuleCount: 1, ApplicationCount: 1}
	raw, _ := json.Marshal(map[string]any{"success": true, "data": map[string]any{"latest_version": "v1", "releases": []Release{r, r}}})
	if _, err := selectRelease(raw); err == nil {
		t.Fatal("accepted duplicate version")
	}
}
