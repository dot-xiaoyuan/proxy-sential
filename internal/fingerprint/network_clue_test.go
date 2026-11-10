package fingerprint

import (
	"strings"
	"testing"
)

func TestHostnameOnlyNetworkRoleStaysClue(t *testing.T) {
	got := Default().IdentifySignals(Signals{
		MAC:                  "18:f2:2c:1b:ad:8c",
		Hostnames:            []string{"TL-WDR5620千兆版"},
		DHCPVendorClass:      "MSFT 5.0",
		DHCPRequestedOptions: "1,3,6,15,43,44,46,47,33,121,249",
	})
	if got.DeviceType != "router" {
		t.Fatalf("device type = %q, want router", got.DeviceType)
	}
	if got.DeviceTypeConfidence > hostnameNetworkClueConfidence || got.Confidence > hostnameNetworkClueConfidence {
		t.Fatalf("hostname-only router confidence = type %.2f / overall %.2f, want <= %.2f", got.DeviceTypeConfidence, got.Confidence, hostnameNetworkClueConfidence)
	}
	if got.Model != "TL-WDR5620" {
		t.Fatalf("model = %q, want TL-WDR5620", got.Model)
	}
	if got.ModelConfidence > hostnameNetworkClueConfidence {
		t.Fatalf("hostname-only model confidence = %.2f, want <= %.2f", got.ModelConfidence, hostnameNetworkClueConfidence)
	}
	if got.OSFamily != "" {
		t.Fatalf("network device kept a weak OS: %q", got.OSFamily)
	}
	if !evidenceContains(got.Evidence, "主机名线索") {
		t.Fatalf("missing hostname clue evidence: %v", got.Evidence)
	}
}

func TestIndependentNetworkSignalKeepsRoleConfidence(t *testing.T) {
	got := Default().IdentifySignals(Signals{
		MAC:       "18:f2:2c:1b:ad:8c",
		Hostnames: []string{"TL-WDR5620千兆版"},
		ProtocolFields: map[string][]string{
			"ssdp_model": {"TL-WDR5620"},
		},
	})
	if got.DeviceType != "router" {
		t.Fatalf("device type = %q, want router", got.DeviceType)
	}
	if got.DeviceTypeConfidence < .85 {
		t.Fatalf("corroborated router confidence = %.2f, want >= .85", got.DeviceTypeConfidence)
	}
	if evidenceContains(got.Evidence, "主机名线索") {
		t.Fatalf("unexpected hostname clue downgrade: %v", got.Evidence)
	}
}

func TestNetworkDeviceWeakOSIsSuppressed(t *testing.T) {
	got := Result{
		DeviceType:           "router",
		DeviceTypeConfidence: .9,
		Model:                "TL-WDR5620",
		ModelConfidence:      .9,
		Brand:                "TP-Link",
		BrandConfidence:      .9,
		Vendor:               "TP-LINK TECHNOLOGIES CO.,LTD.",
		OSFamily:             "Windows",
		OSFamilyConfidence:   .51,
		DimensionEvidence: []DimensionEvidence{
			{Dimension: "device_type", Value: "router", Layer: "device_rule", Field: "hostname", Confidence: .9},
			{Dimension: "model", Value: "TL-WDR5620", Layer: "device_rule", Field: "hostname", Confidence: .9},
			{Dimension: "brand", Value: "TP-Link", Layer: "device_rule", Field: "hostname", Confidence: .9},
			{Dimension: "os_family", Value: "Windows", Layer: "fingerbank_dhcp", Field: "dhcp_requested_options", Confidence: .51},
		},
	}
	applyNetworkDeviceAmbiguityPolicy(&got, Signals{})
	if got.DeviceTypeConfidence != hostnameNetworkClueConfidence {
		t.Fatalf("type confidence = %.2f, want %.2f", got.DeviceTypeConfidence, hostnameNetworkClueConfidence)
	}
	if got.ModelConfidence != hostnameNetworkClueConfidence {
		t.Fatalf("model confidence = %.2f, want %.2f", got.ModelConfidence, hostnameNetworkClueConfidence)
	}
	if got.BrandConfidence != .9 {
		t.Fatalf("OUI-corroborated brand confidence = %.2f, want .90", got.BrandConfidence)
	}
	if got.OSFamily != "" || got.OSFamilyConfidence != 0 {
		t.Fatalf("weak network OS was kept: %q %.2f", got.OSFamily, got.OSFamilyConfidence)
	}
	for _, entry := range got.DimensionEvidence {
		if entry.Dimension == "os_family" {
			t.Fatalf("weak OS dimension evidence was kept: %+v", entry)
		}
	}
	if !evidenceContains(got.Evidence, "已忽略 Windows") {
		t.Fatalf("missing OS suppression evidence: %v", got.Evidence)
	}
}

func TestDesktopOSIsNotSuppressed(t *testing.T) {
	got := Result{
		DeviceType:           "desktop",
		DeviceTypeConfidence: .9,
		OSFamily:             "Windows",
		OSFamilyConfidence:   .9,
		DimensionEvidence: []DimensionEvidence{
			{Dimension: "device_type", Value: "desktop", Layer: "device_rule", Field: "hostname", Confidence: .9},
			{Dimension: "os_family", Value: "Windows", Layer: "fingerbank_dhcp", Field: "dhcp_requested_options", Confidence: .9},
		},
	}
	applyNetworkDeviceAmbiguityPolicy(&got, Signals{})
	if got.OSFamily != "Windows" || got.OSFamilyConfidence != .9 {
		t.Fatalf("desktop OS changed: %q %.2f", got.OSFamily, got.OSFamilyConfidence)
	}
}

func TestNetworkDeviceStrongOSIsKept(t *testing.T) {
	got := Result{
		DeviceType:           "router",
		DeviceTypeConfidence: .9,
		OSFamily:             "RouterOS",
		OSFamilyConfidence:   .8,
		DimensionEvidence: []DimensionEvidence{
			{Dimension: "device_type", Value: "router", Layer: "protocol_catalog", Field: "ssdp_model", Confidence: .8},
			{Dimension: "os_family", Value: "RouterOS", Layer: "protocol_catalog", Field: "http_server", Confidence: .8},
		},
	}
	applyNetworkDeviceAmbiguityPolicy(&got, Signals{})
	if got.DeviceTypeConfidence != .9 {
		t.Fatalf("independent router confidence changed: %.2f", got.DeviceTypeConfidence)
	}
	if got.OSFamily != "RouterOS" || got.OSFamilyConfidence != .8 {
		t.Fatalf("strong router OS changed: %q %.2f", got.OSFamily, got.OSFamilyConfidence)
	}
}

func evidenceContains(evidence []string, want string) bool {
	for _, line := range evidence {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}

func TestTPLinkRouterHostnameDoesNotBecomeWindowsRouter(t *testing.T) {
	rules := []byte(`[{"pattern":"\\b(TL[- _]?(?:WDR|XDR|WR|WTR|ER|MR)[0-9]{3,5}[A-Z]{0,4})","brand":"TP-Link","model_replacement":"$1","device_type":"router","confidence":0.9}]`)
	dhcp := []byte(`[{"requested_options":"1,3,6,15,43,44,46,47,33,121,249","device_type":"desktop","os_family":"Windows","confidence":0.51,"description":"Windows OS"}]`)
	lib, err := LoadWithData("test", []byte("Assignment,Organization Name\n18F22C,TP-LINK TECHNOLOGIES CO.,LTD.\n"), rules, dhcp, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	got := lib.IdentifySignals(Signals{
		MAC:                  "18:f2:2c:1b:ad:8c",
		Hostnames:            []string{"TL-WDR5620千兆版"},
		DHCPVendorClass:      "MSFT 5.0",
		DHCPRequestedOptions: "1,3,6,15,43,44,46,47,33,121,249",
	})
	if got.DeviceType != "router" || got.DeviceTypeConfidence > hostnameNetworkClueConfidence {
		t.Fatalf("hostname-only router = %q %.2f, want router <= %.2f", got.DeviceType, got.DeviceTypeConfidence, hostnameNetworkClueConfidence)
	}
	if got.OSFamily != "" || got.OSFamilyConfidence != 0 {
		t.Fatalf("router kept DHCP Windows OS: %q %.2f", got.OSFamily, got.OSFamilyConfidence)
	}
	if !evidenceContains(got.Evidence, "已忽略 Windows") {
		t.Fatalf("missing suppressed OS note: %v", got.Evidence)
	}
}
