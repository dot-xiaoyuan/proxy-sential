package store

import (
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

func TestPassiveDiscoveryHintEnrichesEndpointRecognition(t *testing.T) {
	profile := EndpointIdentityProfile{
		EndpointID: "mac:0e:df:fe:48:d4:08",
		Endpoint: EndpointEntity{
			EndpointID: "mac:0e:df:fe:48:d4:08",
			PrimaryMAC: "0e:df:fe:48:d4:08",
			EntityRole: "endpoint",
			Attributes: map[string]any{"hostname": "Mac"},
		},
		DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{
			Value: "刘璐的mac mini", Origin: "dns_sd", ObservationID: "dns-sd-test", ObservedAt: time.Now().UTC(),
		}},
	}

	item := BuildEndpointDeviceInventory(profile)
	if item.Brand != "Apple" || item.Model != "Mac mini" || item.DeviceType != "desktop" || item.OSFamily != "macOS" {
		t.Fatalf("passive discovery did not enrich endpoint recognition: %+v", item)
	}
	if item.RecognitionSource != "passive_discovery" || item.RecognitionConfidence < .9 {
		t.Fatalf("passive discovery source/confidence was not retained: %+v", item)
	}
	if len(item.RecognitionEvidence) == 0 || !strings.Contains(strings.Join(item.RecognitionEvidence, " "), "DNS-SD") {
		t.Fatalf("passive discovery evidence is not traceable: %+v", item.RecognitionEvidence)
	}
}

func TestSameConclusionStillKeepsDiscoveryEvidenceReference(t *testing.T) {
	profile := EndpointIdentityProfile{
		EndpointID: "mac:02:00:00:00:00:19",
		Endpoint: EndpointEntity{
			EndpointID: "mac:02:00:00:00:00:19", PrimaryMAC: "02:00:00:00:00:19",
			EntityRole: "endpoint", Attributes: map[string]any{"hostname": "Mac mini"},
		},
		DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{
			Value: "Mac mini", Field: "hostname", Origin: "dns_sd",
			ObservationID: "current-dns-sd-event", ObservedAt: time.Now().UTC(),
		}},
	}
	item := BuildEndpointDeviceInventory(profile)
	if item.Model != "Mac mini" {
		t.Fatalf("expected model recognition: %+v", item)
	}
	if len(item.EvidenceRefs) == 0 || item.EvidenceRefs[0].EventID != "current-dns-sd-event" {
		t.Fatalf("matching discovery observation lost its event reference: %+v", item.EvidenceRefs)
	}
	if item.RecognitionDiagnostics.AcceptedSignals < 2 {
		t.Fatalf("matching discovery observation absent from diagnostics: %+v", item.RecognitionDiagnostics)
	}
}

func TestPassiveDiscoveryHintKeepsExplicitConflictVisible(t *testing.T) {
	profile := EndpointIdentityProfile{
		EndpointID: "mac:00:11:22:33:44:55",
		Endpoint: EndpointEntity{
			EndpointID: "mac:00:11:22:33:44:55",
			PrimaryMAC: "00:11:22:33:44:55",
			EntityRole: "endpoint",
			Attributes: map[string]any{"os_family": "Linux"},
		},
		DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{Value: "Office Mac mini", Origin: "dns_sd"}},
	}

	item := BuildEndpointDeviceInventory(profile)
	if item.OSFamily != "Linux" || !item.RecognitionConflict {
		t.Fatalf("explicit evidence must remain authoritative and conflict visible: %+v", item)
	}
}

func TestTypedDiscoveryModelHintResolvesMarketingName(t *testing.T) {
	profile := EndpointIdentityProfile{
		EndpointID: "mac:02:11:22:33:44:55",
		Endpoint: EndpointEntity{
			EndpointID: "mac:02:11:22:33:44:55",
			PrimaryMAC: "02:11:22:33:44:55",
			EntityRole: "endpoint",
			Attributes: map[string]any{},
		},
		DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{
			Value: "ADY-AL00", Field: "ssdp_model", Origin: "ssdp", ObservationID: "ssdp-model-test", ObservedAt: time.Now().UTC(),
		}},
	}

	item := BuildEndpointDeviceInventory(profile)
	if item.Brand != "Huawei" || item.Model != "Pura 70" || item.DeviceType != "mobile" {
		t.Fatalf("ssdp_model hint did not resolve the marketing name: %+v", item)
	}
	if item.RecognitionSource != "passive_discovery" {
		t.Fatalf("typed hint source was not recorded: %+v", item)
	}
	evidence := strings.Join(item.RecognitionEvidence, " ")
	if !strings.Contains(evidence, "SSDP") || !strings.Contains(evidence, "ssdp_model") {
		t.Fatalf("typed hint evidence is not traceable: %+v", item.RecognitionEvidence)
	}
}

func TestSNMPSelfReportHintResolvesVendor(t *testing.T) {
	profile := EndpointIdentityProfile{
		EndpointID: "mac:02:11:22:33:44:56",
		Endpoint: EndpointEntity{
			EndpointID: "mac:02:11:22:33:44:56",
			PrimaryMAC: "02:11:22:33:44:56",
			EntityRole: "endpoint",
			Attributes: map[string]any{},
		},
		// A locally administered address skips the OUI lookup, so the device's
		// own sysObjectID is the only vendor evidence.
		DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{
			Value: "1.3.6.1.4.1.2011.2.23", Field: "snmp_sysoid", Origin: "snmp", ObservationID: "snmp-sysoid-test", ObservedAt: time.Now().UTC(),
		}},
	}

	item := BuildEndpointDeviceInventory(profile)
	if item.Vendor == "" {
		t.Fatalf("sysObjectID hint did not resolve a vendor: %+v", item)
	}
	if item.RecognitionSource != "passive_discovery" {
		t.Fatalf("vendor-only self-report must still be attributed: %+v", item)
	}
	if !strings.Contains(strings.Join(item.RecognitionEvidence, " "), "snmp_sysoid") {
		t.Fatalf("sysObjectID evidence is not traceable: %+v", item.RecognitionEvidence)
	}
}

func TestTypedDiscoveryHintRoutesToFieldScopedRule(t *testing.T) {
	previous := fingerprint.Default()
	library := fingerprint.MustLoad("typed-hint", []byte("Assignment,Organization Name\n000000,Test\n"), []byte(`[
		{"pattern":"\\bTP-Link\\b","input":"ssdp_manufacturer","brand":"TP-Link","device_type":"router","confidence":0.9}
	]`))
	fingerprint.SetDefault(library)
	defer fingerprint.SetDefault(previous)

	base := EndpointIdentityProfile{
		EndpointID: "mac:02:11:22:33:44:57",
		Endpoint: EndpointEntity{
			EndpointID: "mac:02:11:22:33:44:57",
			PrimaryMAC: "02:11:22:33:44:57",
			EntityRole: "endpoint",
			Attributes: map[string]any{},
		},
	}
	typed := base
	typed.DiscoveryRecognitionHints = []DiscoveryRecognitionHint{{Value: "TP-Link", Field: "ssdp_manufacturer", Origin: "ssdp"}}
	if item := BuildEndpointDeviceInventory(typed); item.Brand != "TP-Link" {
		t.Fatalf("ssdp_manufacturer rule was not routed its own field: %+v", item)
	}

	generic := base
	generic.DiscoveryRecognitionHints = []DiscoveryRecognitionHint{{Value: "TP-Link", Origin: "ssdp"}}
	if item := BuildEndpointDeviceInventory(generic); item.Brand != "" {
		t.Fatalf("field-scoped rule must not inspect generic hints: %+v", item)
	}
}

func TestUsableRecognitionFieldValueBounds(t *testing.T) {
	cases := []struct {
		field, value string
		want         bool
	}{
		{"ssdp_model", "ADY-AL00", true},
		{"ssdp_model", "  ADY-AL00  ", true},
		{"ssdp_model", "", false},
		{"ssdp_model", strings.Repeat("m", 128), true},
		{"ssdp_model", strings.Repeat("m", 129), false},
		{"snmp_sysdescr", strings.Repeat("d", 512), true},
		{"snmp_sysdescr", strings.Repeat("d", 513), false},
		{"snmp_sysoid", "1.3.6.1.4.1.2011.2.23", true},
		{"snmp_sysoid", "1.3.6.1.4.1.\n2011", false},
		{"ssdp_model", "AX55\x01", false},
	}
	for _, tc := range cases {
		if got := usableRecognitionFieldValue(tc.field, tc.value); got != tc.want {
			t.Fatalf("usableRecognitionFieldValue(%q, %q) = %v, want %v", tc.field, tc.value, got, tc.want)
		}
	}
}

func TestEmptyMaterializedRecognitionCannotErasePassiveResult(t *testing.T) {
	current := EndpointDeviceInventory{
		Brand: "Apple", Model: "Mac mini", DeviceType: "desktop", OSFamily: "macOS",
		RecognitionConfidence: .95, RecognitionSource: "passive_discovery",
	}
	cached := EndpointDeviceInventory{RecognitionConfidence: .9, RecognitionSource: "ieee_oui"}
	if materializedRecognitionPreferred(current, cached) {
		t.Fatal("less specific cached recognition would erase current passive evidence")
	}
	cached = current
	if !materializedRecognitionPreferred(current, cached) {
		t.Fatal("equivalent materialized recognition should remain reusable")
	}
}

func TestExplicitAttributesKeepConflictsScopedAndEvidence(t *testing.T) {
	item := BuildEndpointDeviceInventory(EndpointIdentityProfile{Endpoint: EndpointEntity{Attributes: map[string]any{"brand": "Dell", "model": "Latitude", "os_family": "Windows"}}, DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{Value: "iPhone14,5", Field: "ssdp_model", Origin: "ssdp", ObservationID: "iphone"}}})
	if item.Brand != "Dell" || item.Model != "Latitude" || item.OSFamily != "Windows" || item.BrandConfidence != 1 || !deviceDimensionConflict(item, "brand") || !deviceDimensionConflict(item, "model") || deviceDimensionConflict(item, "os_family") {
		t.Fatalf("explicit fields lost scope: %+v", item)
	}
	found := false
	for _, entry := range item.DimensionEvidence {
		if entry.Dimension == "brand" && entry.Layer == "explicit_standard_field" && entry.Value == "Dell" {
			found = true
		}
	}
	if !found {
		t.Fatal("explicit conclusion has no dimension evidence")
	}
}
