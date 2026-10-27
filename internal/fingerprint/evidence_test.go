package fingerprint

import (
	"testing"
	"time"
)

func TestIdentifyEvidenceKeepsDirectionAndLifetime(t *testing.T) {
	library := MustLoad("typed-test", []byte("Assignment,Organization Name\n000000,Test\n"), []byte(`[{"pattern":"AX55","input":"ssdp_model","brand":"TP-Link","model":"Archer AX55","device_type":"router","confidence":0.9}]`))
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	items := []EvidenceSignal{
		{Protocol: "http", Field: "http_server", Value: "HP HTTP Server", Direction: "client", Association: "mac", EventID: "wrong-side", ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)},
		{Protocol: "ssdp", Field: "ssdp_model", Value: "Archer AX55", Direction: "device", Association: "mac", EventID: "expired", ObservedAt: now.Add(-time.Hour), ValidUntil: now.Add(-time.Minute)},
		{Protocol: "ssdp", Field: "ssdp_model", Value: "Archer AX55", Direction: "device", Association: "ambiguous", EventID: "unattributed", ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)},
	}
	got := library.IdentifyEvidence("02:00:00:00:00:01", items, now)
	if got.Brand != "" || got.Model != "" || got.DeviceType != "" || got.Diagnostics.Reason != "unattributed" {
		t.Fatalf("unusable evidence promoted a physical device: %+v", got)
	}
	items = append(items, EvidenceSignal{Protocol: "ssdp", Field: "ssdp_model", Value: "Archer AX55", Direction: "device", Association: "mac", EventID: "valid", ObservedAt: now.Add(-time.Second), ValidUntil: now.Add(time.Minute)})
	got = library.IdentifyEvidence("02:00:00:00:00:01", items, now)
	if got.Brand != "TP-Link" || got.DeviceType != "router" || got.Diagnostics.Stage != "model" {
		t.Fatalf("current self-report was not classified: %+v", got)
	}
	if len(got.EvidenceRefs) != 1 || got.EvidenceRefs[0].EventID != "valid" {
		t.Fatalf("evidence reference was not scoped: %+v", got.EvidenceRefs)
	}
}

func TestIdentifyEvidenceDoesNotPromoteClientFeatures(t *testing.T) {
	now := time.Now().UTC()
	items := []EvidenceSignal{
		{Protocol: "http", Field: "user_agent", Value: "iPhone", Direction: "client", Association: "mac", EventID: "ua", ObservedAt: now, ValidUntil: now.Add(time.Minute)},
		{Protocol: "tls", Field: "ja4", Value: "test", Direction: "client", Association: "mac", EventID: "ja4", ObservedAt: now, ValidUntil: now.Add(time.Minute)},
	}
	got := Default().IdentifyEvidence("02:00:00:00:00:01", items, now)
	if got.Brand != "" || got.Model != "" || got.DeviceType != "" || got.Diagnostics.Reason != "insufficient_specificity" {
		t.Fatalf("client signals established hardware: %+v", got)
	}
}

func TestEvidenceRejectsCrossProtocolProductField(t *testing.T) {
	now := time.Now().UTC()
	items := []EvidenceSignal{{Protocol: "http", Field: "snmp_sysoid", Value: "1.3.6.1.4.1.2011.2.23", Direction: "device", Association: "mac", ObservedAt: now, ValidUntil: now.Add(time.Minute)}}
	got := Default().IdentifyEvidence("02:11:22:33:44:55", items, now)
	if got.Vendor != "" || len(got.Diagnostics.Protocols) != 0 {
		t.Fatalf("cross-protocol field established vendor: %+v", got)
	}
}

func TestClientCatalogMatchCannotEstablishHardware(t *testing.T) {
	got := Result{}
	applySourceMatches(&got, []SourceMatch{{Strength: "self_report", Fields: []string{"user_agent"}, Brand: "Apple", Model: "iPhone", Role: "mobile"}})
	if got.Brand != "" || got.Model != "" || got.DeviceType != "" {
		t.Fatalf("client signature established hardware: %+v", got)
	}
}
