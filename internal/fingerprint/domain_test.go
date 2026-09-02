package fingerprint

import (
	"strings"
	"testing"
	"time"
)

func TestDomainSignatureValidationRejectsConflictsAndConfidenceEscalation(t *testing.T) {
	tests := []struct{ name, rules, want string }{
		{"conflicting ecosystem", `[{"domain":"push.example","match_type":"subdomain","ecosystem":"Apple","category":"push","confidence":0.55,"source":"NextDNS"},{"domain":"push.example","match_type":"subdomain","ecosystem":"Huawei","category":"push","confidence":0.55,"source":"project"}]`, "conflicting"},
		{"nextdns confidence", `[{"domain":"push.example","match_type":"exact","ecosystem":"Apple","category":"push","confidence":0.7,"source":"NextDNS"}]`, "confidence cap"},
		{"runtime regex", `[{"domain":".*\\.apple.com","match_type":"subdomain","ecosystem":"Apple","category":"push","confidence":0.55,"source":"NextDNS"}]`, "invalid domain"},
	}
	for _, item := range tests {
		_, _, err := parseDomainSignatures([]byte(item.rules))
		if err == nil || !strings.Contains(err.Error(), item.want) {
			t.Fatalf("%s: expected %q, got %v", item.name, item.want, err)
		}
	}
}

func TestDomainSignatureBuildDeduplicatesSameEcosystemEntries(t *testing.T) {
	rule := DomainSignature{Domain: "push.apple.example", MatchType: DomainMatchSubdomain, Ecosystem: "Apple", Category: "push", Confidence: 0.55, Source: "NextDNS"}
	data, err := encodeDomainSignatures([]DomainSignature{rule, rule})
	if err != nil {
		t.Fatal(err)
	}
	rules, _, err := parseDomainSignatures(data)
	if err != nil || len(rules) != 1 {
		t.Fatalf("same-ecosystem duplicate should be collapsed: rules=%d err=%v", len(rules), err)
	}
}

func TestDomainMatcherUsesLabelBoundariesAndExactRules(t *testing.T) {
	rules := []byte(`[
{"domain":"apple.com","match_type":"subdomain","ecosystem":"Apple","category":"device_cloud","confidence":0.55,"source":"NextDNS"},
{"domain":"exact.xiaomi.com","match_type":"exact","ecosystem":"Xiaomi","category":"push","confidence":0.55,"source":"NextDNS"}
]`)
	library, err := LoadWithDomainData("test", embeddedOUI, []byte("[]"), []byte("[]"), embeddedBrandAliases, rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"apple.com", "push.apple.com", "PUSH.APPLE.COM.:443"} {
		match, ok := library.MatchDomain(domain)
		if !ok || match.Ecosystem != "Apple" {
			t.Fatalf("expected Apple match for %s: %+v", domain, match)
		}
	}
	for _, domain := range []string{"fakeapple.com", "otherexact.xiaomi.com", "sub.exact.xiaomi.com"} {
		if match, ok := library.MatchDomain(domain); ok {
			t.Fatalf("unexpected match for %s: %+v", domain, match)
		}
	}
	if match, ok := library.MatchDomain("exact.xiaomi.com"); !ok || match.Ecosystem != "Xiaomi" {
		t.Fatalf("exact match failed: %+v", match)
	}
}

func TestDomainMatcherCoversInitialEightEcosystems(t *testing.T) {
	rules := []byte(`[
{"domain":"alexa.example","match_type":"subdomain","ecosystem":"Amazon Alexa","category":"device_cloud","confidence":0.55,"source":"NextDNS"},
{"domain":"apple.example","match_type":"subdomain","ecosystem":"Apple","category":"push","confidence":0.55,"source":"NextDNS"},
{"domain":"huawei.example","match_type":"subdomain","ecosystem":"Huawei","category":"telemetry","confidence":0.55,"source":"NextDNS"},
{"domain":"roku.example","match_type":"subdomain","ecosystem":"Roku","category":"device_cloud","confidence":0.55,"source":"NextDNS"},
{"domain":"samsung.example","match_type":"subdomain","ecosystem":"Samsung","category":"update","confidence":0.55,"source":"NextDNS"},
{"domain":"sonos.example","match_type":"subdomain","ecosystem":"Sonos","category":"device_cloud","confidence":0.55,"source":"NextDNS"},
{"domain":"windows.example","match_type":"subdomain","ecosystem":"Microsoft Windows","category":"update","confidence":0.55,"source":"NextDNS"},
{"domain":"xiaomi.example","match_type":"subdomain","ecosystem":"Xiaomi","category":"telemetry","confidence":0.55,"source":"NextDNS"}
]`)
	library, err := LoadWithDomainData("eight-ecosystems", embeddedOUI, []byte("[]"), []byte("[]"), embeddedBrandAliases, rules)
	if err != nil {
		t.Fatal(err)
	}
	for domain, ecosystem := range map[string]string{
		"device.alexa.example": "Amazon Alexa", "push.apple.example": "Apple",
		"cloud.huawei.example": "Huawei", "api.roku.example": "Roku",
		"update.samsung.example": "Samsung", "music.sonos.example": "Sonos",
		"update.windows.example": "Microsoft Windows", "telemetry.xiaomi.example": "Xiaomi",
	} {
		match, ok := library.MatchDomain(domain)
		if !ok || match.Ecosystem != ecosystem {
			t.Fatalf("expected %s for %s, got %+v", ecosystem, domain, match)
		}
	}
	for _, domain := range []string{"shared.cdn.example", "www.apple.com", "device.alexa.example.evil.test"} {
		if match, ok := library.MatchDomain(domain); ok {
			t.Fatalf("ordinary/shared/lookalike domain %s unexpectedly matched %+v", domain, match)
		}
	}
}

func TestEcosystemConfidenceDisplayAndConflictRules(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	apple := func(domain string, count int, span time.Duration) DomainEvidence {
		return DomainEvidence{Match: DomainMatch{Domain: domain, Ecosystem: "Apple", Confidence: 0.55}, Count: count, FirstSeen: now.Format(time.RFC3339Nano), LastSeen: now.Add(span).Format(time.RFC3339Nano)}
	}
	if result := EvaluateEcosystem([]DomainEvidence{apple("push.apple.com", 100, time.Minute)}); result.Displayable || result.Confidence != 0.55 {
		t.Fatalf("repetition must not raise confidence or display early: %+v", result)
	}
	if result := EvaluateEcosystem([]DomainEvidence{apple("push.apple.com", 3, 10*time.Minute)}); !result.Displayable || result.Confidence != 0.55 {
		t.Fatalf("time-spanning evidence should display: %+v", result)
	}
	result := EvaluateEcosystem([]DomainEvidence{apple("push.apple.com", 1, 0), apple("updates.apple.com", 1, 0)})
	if !result.Displayable || result.Confidence < 0.599 || result.Confidence > 0.601 || result.DistinctDomains != 2 {
		t.Fatalf("distinct evidence bonus failed: %+v", result)
	}
	huawei := DomainEvidence{Match: DomainMatch{Domain: "cloud.huawei.com", Ecosystem: "Huawei", Confidence: 0.55}, Count: 3, FirstSeen: now.Format(time.RFC3339Nano), LastSeen: now.Add(15 * time.Minute).Format(time.RFC3339Nano)}
	if conflict := EvaluateEcosystem(append([]DomainEvidence{apple("push.apple.com", 3, 15*time.Minute)}, huawei)); !conflict.Conflict || conflict.Displayable {
		t.Fatalf("ecosystem conflict not detected: %+v", conflict)
	}
}

func TestEcosystemCannotCreateBrandAndOUIDoesNotPromote(t *testing.T) {
	ecosystem := EcosystemResult{Hint: "Apple", Confidence: 0.60, Displayable: true}
	if brand, confidence, promoted := FuseEcosystemBrand("", 0, "", ecosystem); brand != "" || confidence != 0 || promoted {
		t.Fatal("domain evidence created a brand")
	}
	if _, confidence, promoted := FuseEcosystemBrand("Apple", 0.9, "ieee_oui", ecosystem); confidence != 0.9 || promoted {
		t.Fatal("OUI must not jointly prove brand")
	}
	if brand, confidence, promoted := FuseEcosystemBrand("Apple", 0.7, "device_rule", ecosystem); brand != "Apple" || confidence < 0.8 || !promoted {
		t.Fatalf("independent agreeing evidence not fused: %s %.2f %v", brand, confidence, promoted)
	}
	if _, _, promoted := FuseEcosystemBrand("Samsung", 0.9, "device_rule", ecosystem); promoted {
		t.Fatal("conflicting brand was promoted")
	}
}

func TestBundleV1RemainsImportableWithoutDomainRules(t *testing.T) {
	bundle, err := VerifyBundleBytes(testBundleBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.SchemaVersion != BundleSchemaVersionV1 || len(bundle.Files["domain-signatures.json"]) != 0 {
		t.Fatalf("unexpected v1 bundle: %+v", bundle.Manifest)
	}
}
