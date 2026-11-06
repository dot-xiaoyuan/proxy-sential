package fingerprint

import (
	"encoding/json"
	"strings"
	"testing"
)

func rawRecords(t *testing.T, records []FingerbankRawRecord) []byte {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCompileFingerbankSnapshotMapsDeviceFamilies(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1, 3, 6, 15"}, VendorClasses: []string{"MSFT 5.0"}, DevicePath: "Operating System/Windows OS"},
		{Fingerprints: []string{"1,33,3,6"}, DevicePath: "Hardware/Printer/HP LaserJet"},
		{Fingerprints: []string{"1,121,3,6"}, DevicePath: "Phone, Tablet or Wearable/Generic Android"},
		{Fingerprints: []string{"1,2,3"}, DevicePath: "Mystery Box"},
		{Fingerprints: []string{""}, DevicePath: "Operating System/Windows OS"},
	})
	compiled, stats, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1, MaxUnmappedRate: 0.5})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var items []DHCPFingerprint
	if err = json.Unmarshal(compiled, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("emitted=%d want 3 (%+v)", len(items), items)
	}
	byOptions := map[string]DHCPFingerprint{}
	for _, item := range items {
		byOptions[item.RequestedOptions] = item
	}
	if got := byOptions["1,3,6,15"]; got.DeviceType != "desktop" || got.OSFamily != "Windows" || len(got.VendorClasses) != 1 {
		t.Fatalf("windows rule wrong: %+v", got)
	}
	if got := byOptions["1,33,3,6"]; got.DeviceType != "printer" {
		t.Fatalf("printer rule wrong: %+v", got)
	}
	if got := byOptions["1,121,3,6"]; got.DeviceType != "" || got.OSFamily != "Android" {
		t.Fatalf("generic android must remain OS-only: %+v", got)
	}
	// A row whose device family cannot be mapped is dropped, not guessed.
	if _, ok := byOptions["1,2,3"]; ok {
		t.Fatal("unmapped rule must not be emitted")
	}
	if stats.UnmappedRules != 1 || stats.MalformedRows != 1 {
		t.Fatalf("stats unmapped=%d malformed=%d", stats.UnmappedRules, stats.MalformedRows)
	}
	for _, item := range items {
		if item.Confidence != fingerbankDefaultConfidence {
			t.Fatalf("rule confidence=%v", item.Confidence)
		}
	}
	if stats.Confidence != fingerbankDefaultConfidence {
		t.Fatalf("stats confidence=%v", stats.Confidence)
	}
}

func TestCompileFingerbankSnapshotDeduplicatesAndUnionsVendors(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1,3,6"}, VendorClasses: []string{"MSFT 5.0"}, DevicePath: "Operating System"},
		{Fingerprints: []string{"1,3,6"}, VendorClasses: []string{"MSFT 5.0 ", "MSFT 6.0"}, DevicePath: "Operating System/Windows OS"},
	})
	compiled, stats, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var items []DHCPFingerprint
	if err = json.Unmarshal(compiled, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("emitted=%d want 1", len(items))
	}
	if stats.Distinct != 1 {
		t.Fatalf("distinct=%d", stats.Distinct)
	}
	// The longer device path wins and both vendor classes are preserved.
	if items[0].Description != "Windows OS" {
		t.Fatalf("description=%q", items[0].Description)
	}
	if len(items[0].VendorClasses) != 2 {
		t.Fatalf("vendors=%v", items[0].VendorClasses)
	}
}

func TestCompileFingerbankSnapshotIsDeterministic(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1,3,6,15"}, DevicePath: "Operating System/Windows OS"},
		{Fingerprints: []string{"1,33,3,6"}, DevicePath: "Hardware/Printer"},
	})
	first, _, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("compiled snapshot is not deterministic")
	}
	if !strings.Contains(string(first), `"printer"`) {
		t.Fatalf("compiled payload missing printer: %s", first)
	}
}

func TestCompileFingerbankSnapshotRejectsThinSnapshots(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1,3,6"}, DevicePath: "Operating System/Windows OS"},
	})
	if _, _, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 10}); err == nil {
		t.Fatal("expected thin snapshot to fail")
	}
	mixed := []FingerbankRawRecord{
		{Fingerprints: []string{"1,3,6"}, DevicePath: "Operating System/Windows OS"},
	}
	for _, options := range []string{"1,3", "1,3,6,15", "1,3,6,15,28", "1,3,6,15,28,51", "1,3,6,15,28,51,58"} {
		mixed = append(mixed, FingerbankRawRecord{Fingerprints: []string{options}, DevicePath: "Mystery"})
	}
	if _, _, err := CompileFingerbankSnapshot(rawRecords(t, mixed), FingerbankCompileOptions{MinRules: 1, MaxUnmappedRate: 0.2}); err == nil {
		t.Fatal("expected unmapped rate to fail")
	}
}

func TestCompileFingerbankSnapshotRejectsInvalidJSON(t *testing.T) {
	if _, _, err := CompileFingerbankSnapshot([]byte("not json"), FingerbankCompileOptions{}); err == nil {
		t.Fatal("expected invalid json to fail")
	}
}

func TestCompileFingerbankSnapshotUsesScoreConfidence(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1,3,6"}, DevicePath: "Operating System/Windows OS", Score: 92},
		{Fingerprints: []string{"1,3,6,15"}, DevicePath: "Operating System/Windows OS", Score: 40},
		{Fingerprints: []string{"1,3,6,15,28"}, DevicePath: "Operating System/Windows OS", Score: 10},
	})
	compiled, stats, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if stats.LowScoreRows != 1 {
		t.Fatalf("low score rows=%d want 1", stats.LowScoreRows)
	}
	var items []DHCPFingerprint
	if err = json.Unmarshal(compiled, &items); err != nil {
		t.Fatal(err)
	}
	confidence := map[string]float64{}
	for _, item := range items {
		confidence[item.RequestedOptions] = item.Confidence
	}
	if got := confidence["1,3,6"]; got != 0.9 {
		t.Fatalf("score 92 confidence=%v want 0.9", got)
	}
	if got := confidence["1,3,6,15"]; got != 0.5 {
		t.Fatalf("score 40 confidence=%v want 0.5", got)
	}
	if _, ok := confidence["1,3,6,15,28"]; ok {
		t.Fatal("score below 30 must not be compiled")
	}
}

func TestNormalizeFingerbankDevicePathExtras(t *testing.T) {
	cases := []struct {
		path     string
		device   string
		osFamily string
	}{
		{"Operating System/Apple OS", "", "Apple OS"},
		{"Operating System/Embedded OS", "", ""},
		{"Operating System/Chrome OS", "desktop", "ChromeOS"},
		{"Hardware/IP Camera", "camera", ""},
		{"Firewall and Security Appliance/Ruijie Firewall", "firewall", ""},
		{"Phone, Tablet or Wearable/Generic Android/Huawei Android", "", "Android"},
		{"Phone, Tablet or Wearable/Smartphone/Android Phone", "mobile", "Android"},
		{"Router, Access Point or Femtocell", "", ""},
		{"Router, Access Point or Femtocell/Router/Huawei Router", "router", ""},
		{"Router, Access Point or Femtocell/Wireless Access Point/H3C WAP", "access_point", ""},
		{"Operating System/Tizen OS", "", "Tizen"},
		{"VoIP Device/Yealink VoIP", "phone", ""},
		{"Operating System/Windows OS", "desktop", "Windows"},
	}
	for _, tc := range cases {
		device, osFamily := normalizeFingerbankDevicePath(tc.path, "")
		if device != tc.device || osFamily != tc.osFamily {
			t.Fatalf("%s: got (%q,%q) want (%q,%q)", tc.path, device, osFamily, tc.device, tc.osFamily)
		}
	}
}

func TestCompileFingerbankSnapshotKeepsVendorSpecificResults(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1,121,3,6,15"}, VendorClasses: []string{"apple"}, DevicePath: "Operating System/Apple OS", Score: 87},
		{Fingerprints: []string{"1,121,3,6,15"}, VendorClasses: []string{"dhcpcd-15"}, DevicePath: "Operating System/Google OS/Android OS", Score: 52},
	})
	compiled, _, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var items []DHCPFingerprint
	if err = json.Unmarshal(compiled, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("emitted=%d want 2", len(items))
	}
	lib, err := LoadWithData("test", []byte("Assignment,Organization Name\nABCDEF,Example\n"), []byte("[]"), compiled, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ vendor, os string }{
		{"apple", "Apple OS"}, {"dhcpcd-15", "Android"}, {"other", ""}, {"", ""},
	} {
		got := lib.IdentifySignals(Signals{DHCPRequestedOptions: "1,121,3,6,15", DHCPVendorClass: tc.vendor})
		if got.OSFamily != tc.os {
			t.Fatalf("vendor=%q: OS=%q want %q", tc.vendor, got.OSFamily, tc.os)
		}
		if tc.vendor == "dhcpcd-15" && got.OSFamilyConfidence > 0.52 {
			t.Fatalf("vendor-specific score was inflated: %+v", got)
		}
	}
}

func TestCompileFingerbankSnapshotUsesGenericOnlyWithoutVendorMatch(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1,3,6"}, DevicePath: "Operating System/Windows OS", Score: 82},
		{Fingerprints: []string{"1,3,6"}, VendorClasses: []string{"android-dhcp"}, DevicePath: "Phone, Tablet or Wearable/Smartphone/Android Phone", Score: 90},
	})
	compiled, _, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1})
	if err != nil {
		t.Fatal(err)
	}
	lib, err := LoadWithData("test", []byte("Assignment,Organization Name\nABCDEF,Example\n"), []byte("[]"), compiled, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ vendor, deviceType, os string }{
		{"android-dhcp", "mobile", "Android"},
		{"other", "desktop", "Windows"},
		{"", "desktop", "Windows"},
	} {
		got := lib.IdentifySignals(Signals{DHCPRequestedOptions: "1,3,6", DHCPVendorClass: tc.vendor})
		if got.DeviceType != tc.deviceType || got.OSFamily != tc.os {
			t.Fatalf("vendor=%q: got (%q,%q) want (%q,%q)", tc.vendor, got.DeviceType, got.OSFamily, tc.deviceType, tc.os)
		}
	}
}

func TestBroadDHCPFamilyDoesNotReplaceSpecificOSOrTablet(t *testing.T) {
	for _, tc := range []struct{ field, broad, specific string }{
		{"device_type", "mobile", "tablet"},
		{"os_family", "Apple OS", "iOS"},
		{"os_family", "Apple OS", "iPadOS"},
		{"os_family", "Apple OS", "macOS"},
		{"os_family", "Android", "HarmonyOS"},
	} {
		for _, reversed := range []bool{false, true} {
			result := Result{}
			if reversed {
				mergeDimension(&result, tc.field, tc.specific, .82, .85)
				mergeDimension(&result, tc.field, tc.broad, .9, .85)
			} else {
				mergeDimension(&result, tc.field, tc.broad, .9, .85)
				mergeDimension(&result, tc.field, tc.specific, .82, .85)
			}
			value := result.DeviceType
			if tc.field == "os_family" {
				value = result.OSFamily
			}
			if value != tc.specific || result.Conflict {
				t.Fatalf("%s reverse=%t: value=%q conflict=%t want %q", tc.field, reversed, value, result.Conflict, tc.specific)
			}
		}
	}
}

func TestFingerbankDoesNotReplaceExistingUnrelatedOSConclusion(t *testing.T) {
	rules := []byte(`[{"input":"hostname","pattern":"^chromebook-","device_type":"laptop","os_family":"ChromeOS","confidence":0.82}]`)
	dhcp := []byte(`[{"requested_options":"1,3,6","vendor_classes":["MSFT"],"vendor_required":true,"device_type":"desktop","os_family":"Windows","confidence":0.9}]`)
	lib, err := LoadWithData("test", []byte("Assignment,Organization Name\nABCDEF,Example\n"), rules, dhcp, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	got := lib.IdentifySignals(Signals{Hostnames: []string{"chromebook-123"}, DHCPRequestedOptions: "1,3,6", DHCPVendorClass: "MSFT"})
	if got.OSFamily != "ChromeOS" || got.DeviceType != "laptop" {
		t.Fatalf("specific rule was replaced by DHCP: %+v", got)
	}
}

func TestCompileFingerbankSnapshotKeepsDifferentDescriptionsDistinct(t *testing.T) {
	raw := rawRecords(t, []FingerbankRawRecord{
		{Fingerprints: []string{"1,3,6"}, VendorClasses: []string{"printer-vendor"}, Description: "Printer", Score: 80},
		{Fingerprints: []string{"1,3,6"}, VendorClasses: []string{"router-vendor"}, Description: "Router", Score: 80},
	})
	compiled, _, err := CompileFingerbankSnapshot(raw, FingerbankCompileOptions{MinRules: 1})
	if err != nil {
		t.Fatal(err)
	}
	var items []DHCPFingerprint
	if err = json.Unmarshal(compiled, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].DeviceType == items[1].DeviceType {
		t.Fatalf("different interpretations were merged: %+v", items)
	}
}
