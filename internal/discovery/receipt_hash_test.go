package discovery

import (
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"testing"
)

func productReceiptEvent() normalized.Event {
	return normalized.Event{SchemaVersion: "v1", EventID: "product-receipt", Type: "discovery", Source: "passive", SourceEventType: "dns_sd", Timestamp: "2026-10-23T01:00:00Z", Observer: map[string]any{"sensor_id": "test", "source_id": "passive-test"}, Subject: map[string]any{"ip": "10.91.0.1"}, Payload: map[string]any{"origin": "dns_sd", "ttl": 600, "is_response": true, "txt": "model=AppleTV6,2", "service_type": "_airplay._tcp"}}
}
func TestProductRulesPreserveOriginalEventHash(t *testing.T) {
	e := productReceiptEvent()
	before := contentHash(e)
	o, err := FromEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	if contentHash(e) != before {
		t.Fatal("product classification mutated original evidence and receipt hash")
	}
	if o.Evidence.Payload["product_type"] != "media_player" {
		t.Fatal("derived product evidence missing")
	}
}
func TestLegacyReceiptRequiresOriginalBatchEvidence(t *testing.T) {
	e := productReceiptEvent()
	raw, _ := json.Marshal([]normalized.Event{e})
	o, _ := FromEvent(e)
	legacy := contentHash(o.Evidence)
	if !ReceiptMatchesEvent(e, legacy, raw) {
		t.Fatal("verified legacy receipt rejected")
	}
	if ReceiptMatchesEvent(e, legacy, nil) {
		t.Fatal("legacy hash accepted without original batch")
	}
	changed := productReceiptEvent()
	changed.Payload["product_model"] = "a forged value overwritten by classifier"
	if ReceiptMatchesEvent(changed, legacy, raw) {
		t.Fatal("different raw evidence accepted after classification erased difference")
	}
	if ReceiptMatchesEvent(e, "conflict", raw) {
		t.Fatal("conflicting receipt accepted")
	}
}
