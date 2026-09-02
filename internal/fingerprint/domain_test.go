package fingerprint

import (
	"strings"
	"testing"
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

func TestBundleV1RemainsImportableWithoutDomainRules(t *testing.T) {
	bundle, err := VerifyBundleBytes(testBundleBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.SchemaVersion != BundleSchemaVersionV1 || len(bundle.Files["domain-signatures.json"]) != 0 {
		t.Fatalf("unexpected v1 bundle: %+v", bundle.Manifest)
	}
}
