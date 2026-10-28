package discovery

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecognitionInputSeparatesLateWithdrawalAndEmptyFeatures(t *testing.T) {
	item := streamPreparedDiscovery{Protocol: "ssdp"}
	if _, status := recognitionInput(item); status != "parse_error" {
		t.Fatal(status)
	}
	item.Parsed = true
	if _, status := recognitionInput(item); status != "outside_scope" {
		t.Fatal(status)
	}
	item.HasFact = true
	item.Fact.Protocol, item.Fact.EvidenceEvent = "ssdp", "original-event"
	item.Fact.ValidUntil = time.Now().Add(time.Hour)
	if _, status := recognitionInput(item); status != "no_features" {
		t.Fatal(status)
	}
	item.Fact.Withdrawn = true
	input, status := recognitionInput(item)
	if status != "unattributed" || !input.Withdrawn || input.EvidenceEvent != "original-event" {
		t.Fatalf("%+v %s", input, status)
	}
	item.Receipt.Result = "late_history"
	if _, status := recognitionInput(item); status != "superseded" {
		t.Fatal(status)
	}
}

func TestRecognitionAnnotationsStayCompactWithoutCopyingProductValues(t *testing.T) {
	item := streamPreparedDiscovery{Protocol: "ssdp", Parsed: true, HasFact: true}
	item.Fact.Protocol, item.Fact.MAC, item.Fact.IP = "ssdp", "02:00:00:00:00:01", "192.168.1.2"
	item.Fact.Sensor, item.Fact.Site, item.Fact.EvidenceEvent = "sensor", "site", "event-reference"
	item.Fact.Observed, item.Fact.ValidUntil = time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	item.Fact.RecognitionFields = map[string]string{}
	for i := 0; i < 12; i++ {
		item.Fact.RecognitionFields[string(rune('a'+i))] = strings.Repeat("raw-product-value", 30)
	}
	var total int
	for i := 0; i < 10000; i++ {
		input, _ := recognitionInput(item)
		raw, err := json.Marshal(input)
		if err != nil || len(raw) > 2048 || strings.Contains(string(raw), "raw-product-value") {
			t.Fatalf("annotation copied values or exceeded compact budget: bytes=%d err=%v", len(raw), err)
		}
		total += len(raw)
	}
	t.Logf("10000 maximum-field annotations: %d JSON bytes; %d bytes/event", total, total/10000)
	item.Fact.Sensor = strings.Repeat("x", 65536)
	input, status := recognitionInput(item)
	raw, err := json.Marshal(input)
	if err != nil || status != "diagnostic_limit" || len(raw) > 512 || input.MAC != "" {
		t.Fatalf("oversized association metadata must be explicit, without truncating an identity: status=%s bytes=%d", status, len(raw))
	}
}
