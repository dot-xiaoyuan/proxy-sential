package discovery

import (
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"reflect"
	"testing"
)

func TestDiscoveryBatchPreservesBinaryProtocolText(t *testing.T) {
	events := []normalized.Event{{EventID: "binary", Payload: map[string]any{"txt": []any{"model=Printer\x00firmware", `literal=\u0000`}}}}
	raw, err := EncodeDiscoveryBatch(events)
	if err != nil {
		t.Fatal(err)
	}
	var storage any
	if err = json.Unmarshal(raw, &storage); err != nil {
		t.Fatal(err)
	}
	if containsNUL(storage) {
		t.Fatal("JSONB still contains NUL")
	}
	var decoded []normalized.Event
	if err = decodeDiscoveryBatch(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, decoded) {
		t.Fatalf("evidence changed: %#v", decoded)
	}
}
func TestDiscoveryBatchKeepsLegacyArrayReadable(t *testing.T) {
	events := []normalized.Event{{EventID: "ordinary", Payload: map[string]any{"name": "printer"}}}
	raw, _ := json.Marshal(events)
	var decoded []normalized.Event
	if err := decodeDiscoveryBatch(raw, &decoded); err != nil || !reflect.DeepEqual(events, decoded) {
		t.Fatalf("legacy batch: %v", err)
	}
}
