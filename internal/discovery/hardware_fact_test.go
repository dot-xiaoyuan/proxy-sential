package discovery

import (
	"strings"
	"testing"
)

func TestJoinedDNSModelRequiresTheOriginalTXTRecord(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	source := map[string]any{"content_sha256": hash, "ingest_source_ref": map[string]any{"file_id": "original"}}
	txt := map[string]any{"event_id": "zeek-" + hash[:24], "raw_ref": source}
	fact := HardwareFact{Source: "dns_sd", RawRef: map[string]any{"backend": "derived_dns_sd", "records": []any{txt, txt, nil}}}
	if fact.hasReferencedProductRecord() {
		t.Fatal("address reference treated as TXT")
	}
	fact.RawRef["records"] = []any{nil, nil, txt}
	if !fact.hasReferencedProductRecord() {
		t.Fatal("original joined TXT lost")
	}
	txt["record_type"] = "SRV"
	if fact.hasReferencedProductRecord() {
		t.Fatal("non-TXT admitted")
	}
}
