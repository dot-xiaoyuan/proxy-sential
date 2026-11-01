package discovery

import (
	"encoding/json"
	"testing"
)

func eventBusScopedFact() map[string]any {
	return map[string]any{"event_id": "event-a", "protocol": "dns_sd", "ip": "192.0.2.10", "sensor_id": "sensor-a", "site": "campus-a", "domain": "mirror-a", "vlan": "100/101", "vrf": "blue", "interface_name": "bond0"}
}

func TestEventBusCurrentScopeComesOnlyFromCompleteConsistentFactMetadata(t *testing.T) {
	item := map[string]any{"id": "opaque-device-key", "facts": map[string]any{"first": eventBusScopedFact(), "second": eventBusScopedFact()}}
	normalizeEventBusDocument(item)
	for key, want := range map[string]string{"sensor_id": "sensor-a", "site": "campus-a", "domain": "mirror-a", "vlan": "100/101", "vrf": "blue", "interface": "bond0"} {
		if item[key] != want {
			t.Errorf("missing authoritative %s: got=%v want=%s", key, item[key], want)
		}
	}
}

func TestEventBusCurrentScopeDoesNotGuessMissingOrConflictingMetadata(t *testing.T) {
	for _, kind := range []string{"old_facts", "missing_domain", "empty_sensor", "conflicting_domain", "conflicting_vrf", "malformed_fact", "document_conflict", "document_untagged", "document_empty_vrf"} {
		t.Run(kind, func(t *testing.T) {
			first, second := eventBusScopedFact(), eventBusScopedFact()
			item := map[string]any{"id": "sensor-guessed-from-id", "facts": map[string]any{"first": first, "second": second}}
			switch kind {
			case "old_facts":
				delete(first, "sensor_id")
			case "missing_domain":
				delete(first, "domain")
			case "empty_sensor":
				first["sensor_id"] = ""
			case "conflicting_domain":
				second["domain"] = "other-mirror"
			case "conflicting_vrf":
				second["vrf"] = "red"
			case "malformed_fact":
				item["facts"].(map[string]any)["second"] = []any{"invalid"}
			case "document_conflict":
				item["site"] = "another-campus"
			case "document_untagged":
				item["vlan"] = ""
			case "document_empty_vrf":
				item["vrf"] = ""
			}
			normalizeEventBusDocument(item)
			if _, exists := item["sensor_id"]; exists {
				t.Fatalf("scope inferred from incomplete/conflicting data: %+v", item)
			}
			if kind == "document_conflict" && item["site"] != "another-campus" {
				t.Fatal("existing document evidence overwritten")
			}
		})
	}
}

func TestEventBusScopeNormalizationPreservesRichDocumentAndEvidence(t *testing.T) {
	facts := map[string]any{"first": eventBusScopedFact()}
	before, _ := json.Marshal(facts)
	item := map[string]any{"sensor_id": "sensor-a", "site": "campus-a", "domain": "mirror-a", "vlan": "100/101", "interface": "bond0", "name": "Printer", "manufacturer": "Evidence vendor", "facts": facts}
	normalizeEventBusDocument(item)
	after, _ := json.Marshal(facts)
	if string(before) != string(after) || item["name"] != "Printer" || item["manufacturer"] != "Evidence vendor" || item["vrf"] != "blue" {
		t.Fatalf("scope hydration changed evidence/document: %+v", item)
	}
}
