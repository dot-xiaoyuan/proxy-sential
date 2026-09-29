package fingerprint

import (
	"testing"
	"time"
)

func TestBrandInferenceServiceThresholds(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	evidence := func(rule, domain string, count int, span time.Duration) DomainEvidence {
		return DomainEvidence{Match: DomainMatch{Domain: domain, RuleDomain: rule, Ecosystem: "Apple", Confidence: .65, BrandEligible: true, Service: rule}, RuleVersion: "v4", FirstSeen: now.Add(-span).Format(time.RFC3339Nano), LastSeen: now.Format(time.RFC3339Nano), Count: count}
	}
	first := evidence("push.apple.com", "a.push.apple.com", 1, 0)
	for _, tc := range []struct {
		name  string
		items []DomainEvidence
		want  string
	}{
		{"single", []DomainEvidence{first}, "insufficient"},
		{"random subdomains", []DomainEvidence{first, evidence("push.apple.com", "b.push.apple.com", 1, 0)}, "insufficient"},
		{"two services", []DomainEvidence{first, evidence("albert.apple.com", "albert.apple.com", 1, 0)}, "inferred"},
		{"repeat", []DomainEvidence{evidence("push.apple.com", "push.apple.com", 3, 10*time.Minute)}, "inferred"},
		{"burst", []DomainEvidence{evidence("push.apple.com", "push.apple.com", 100, time.Minute)}, "insufficient"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := InferBrand(tc.items, "v4", now, "", 0)
			if got.Status != tc.want || got.Confidence > .70 {
				t.Fatalf("%+v", got)
			}
		})
	}
	repeat := evidence("push.apple.com", "push.apple.com", 3, 10*time.Minute)
	old := repeat
	old.RuleVersion = "v3"
	expired := repeat
	expired.LastSeen = now.Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano)
	weak := repeat
	weak.Match.BrandEligible = false
	for _, item := range []DomainEvidence{old, expired, weak} {
		if got := InferBrand([]DomainEvidence{item}, "v4", now, "", 0); got.Status != "insufficient" {
			t.Fatalf("ineligible: %+v", got)
		}
	}
	other := repeat
	other.Match.Ecosystem = "Huawei"
	other.Match.RuleDomain = "device.huawei.test"
	other.Match.Service = "huawei-device"
	if got := InferBrand([]DomainEvidence{repeat, other}, "v4", now, "", 0); got.Status != "conflict" || len(got.Candidates) != 2 {
		t.Fatalf("conflict: %+v", got)
	}
	if got := InferBrand([]DomainEvidence{repeat}, "v4", now, "Samsung", .9); got.Status != "conflict" {
		t.Fatalf("independent conflict: %+v", got)
	}
}

func TestEcosystemFusionRequiresDisplayableEvidence(t *testing.T) {
	if _, _, promoted := FuseEcosystemBrand("Apple", .7, "device_rule", EcosystemResult{Hint: "Apple", Confidence: .6}); promoted {
		t.Fatal("insufficient domain evidence promoted brand")
	}
}
