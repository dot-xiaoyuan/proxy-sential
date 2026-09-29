package evaluation

import (
	"path/filepath"
	"testing"
)

func TestEvaluateRouterGoldenManifest(t *testing.T) {
	report, err := EvaluateRouters(filepath.Join("..", "..", "examples", "router", "golden", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalSamples < 19 || report.Failed != 0 || report.RouterPrecision != 1 || report.RouterRecall != 1 || report.OUIOnlyMisconfirmed != 0 {
		t.Fatalf("router golden acceptance failed: %+v", report)
	}
	for _, role := range []string{"ap", "switch", "firewall"} {
		if report.RoleFalsePositiveRate[role] != 0 {
			t.Fatalf("unexpected %s false positive rate: %+v", role, report.RoleFalsePositiveRate)
		}
	}
	if report.SourceDistribution["dhcp"] == 0 || report.SourceDistribution["lldp"] == 0 || report.ExpiredEvidence == 0 || report.UnableToAssociate == 0 {
		t.Fatalf("missing required evaluation coverage: %+v", report)
	}
}
