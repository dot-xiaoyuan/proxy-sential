package store

import (
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/fingerprint"
)

func TestDeviceInventoryProjectionDropsDetailHistoriesAndBrandEvidence(t *testing.T) {
	item := EndpointDeviceInventory{
		EndpointID: "mac:00:10:20:30:40:50", Accounts: []string{"account-a"}, IPs: []string{"192.0.2.1"}, AccessIDs: []string{"AP-1"},
		RecognitionEvidence: []string{"large evidence payload"},
		BrandInference: &fingerprint.BrandInference{
			Status: "inferred", Brand: "Apple", Confidence: .65, Explanation: "detail-only explanation",
			RuleVersion: "brand-rules-v1", Window: "7d", AsOf: "2026-09-30T00:00:00Z",
			Candidates: []fingerprint.BrandCandidate{{Brand: "Apple", Confidence: .65}},
		},
	}
	raw, err := json.Marshal(ProjectDeviceInventoryListItem(item))
	if err != nil {
		t.Fatal(err)
	}
	payload := string(raw)
	for _, forbidden := range []string{"accounts", "ips", "access_ids", "recognition_evidence", "candidates", "explanation", "rule_version"} {
		if strings.Contains(payload, `"`+forbidden+`"`) {
			t.Fatalf("list projection leaked %s: %s", forbidden, payload)
		}
	}
	if !strings.Contains(payload, `"brand_inference":{"status":"inferred","brand":"Apple","confidence":0.65}`) {
		t.Fatalf("compact brand inference missing: %s", payload)
	}
}
