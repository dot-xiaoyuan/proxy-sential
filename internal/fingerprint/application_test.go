package fingerprint

import "testing"

func TestGameAcceleratorsAreLicensedNegativeEvidence(t *testing.T) {
	matches := MatchApplication("process=uu-booster")
	if len(matches) != 1 || matches[0].Effect != "negative_evidence" || matches[0].License == "" || matches[0].Version == "" {
		t.Fatalf("unexpected match: %+v", matches)
	}
}
