package risk

import (
	"bytes"
	"fmt"
	"proxy-sentinel/internal/evidence"
	"testing"
)

func TestUnscoredTTLVariationDoesNotChangeRiskOrStrongEvidence(t *testing.T) {
	for _, score := range []int{0, 25, 35, 50} {
		t.Run(fmt.Sprint(score), func(t *testing.T) {
			base := ev("ports", "10.0.0.1", "port_distribution", score, .65)
			before, err := Inspect(bytes.NewReader(evidenceInput(base)), InspectOptions{IP: base.IP})
			if err != nil {
				t.Fatal(err)
			}
			variation := ev("path", "10.0.0.1", "ttl_path_variation", 0, .68)
			after, err := Inspect(bytes.NewReader(evidenceInput(base, variation)), InspectOptions{IP: base.IP})
			if err != nil {
				t.Fatal(err)
			}
			if after.Score != before.Score || after.Level != before.Level || after.Confidence != before.Confidence || after.DetectionBasis != before.DetectionBasis || after.AutomationEligible || len(after.IndependentSignalGroups) != len(before.IndependentSignalGroups) {
				t.Fatalf("zero-score variation changed risk before=%+v after=%+v", before, after)
			}
			if strongEvidenceTypeCount([]evidence.Evidence{variation}) != 0 {
				t.Error("path variation became strong evidence")
			}
			if len(after.EvidenceIDs) != 2 {
				t.Fatal("unscored explanation lost from audit", after)
			}
		})
	}
}

func TestUnscoredTTLVariationDoesNotSuppressExplicitTunnel(t *testing.T) {
	rule := ev("signed-rule", "10.0.0.1", "vpn_proxy_rule_match", 94, .92)
	before, err := Inspect(bytes.NewReader(evidenceInput(rule)), InspectOptions{IP: rule.IP})
	if err != nil {
		t.Fatal(err)
	}
	after, err := Inspect(bytes.NewReader(evidenceInput(rule, ev("path", rule.IP, "ttl_path_variation", 0, .68))), InspectOptions{IP: rule.IP})
	if err != nil {
		t.Fatal(err)
	}
	if before.DetectionBasis != "explicit_tunnel" || after.Score != before.Score || after.Level != before.Level || after.Confidence != before.Confidence || after.DetectionBasis != before.DetectionBasis {
		t.Fatalf("unscored path suppressed explicit protocol proof: before=%+v after=%+v", before, after)
	}
}
