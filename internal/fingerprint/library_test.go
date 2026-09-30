package fingerprint

import "testing"

func TestIdentifyOUIAndDeviceRule(t *testing.T) {
	library := Default()
	vmware := library.Identify("00:0c:29:aa:bb:cc")
	if vmware.Vendor != "VMware, Inc." || vmware.Brand != "" {
		t.Fatalf("unexpected VMware identification: %+v", vmware)
	}
	if vmware.VendorConfidence != .9 || vmware.BrandConfidence != 0 || vmware.ModelConfidence != 0 {
		t.Fatalf("vendor, brand and model confidence must remain independent: %+v", vmware)
	}
	phone := library.Identify("e6:c4:00:00:00:01", "MI9SE-xiaoyingderead", "android-dhcp-10")
	if !phone.RandomizedMAC || phone.Brand != "Xiaomi" || phone.Model != "Mi 9 SE" || phone.DeviceType != "mobile" {
		t.Fatalf("unexpected Xiaomi identification: %+v", phone)
	}
	if phone.BrandConfidence < .8 || phone.ModelConfidence < .8 || phone.DeviceTypeConfidence < .8 || phone.VendorConfidence != 0 {
		t.Fatalf("device rule confidence fields are incorrect: %+v", phone)
	}
}

func TestStandardDeviceRecognitionReplay(t *testing.T) {
	library := Default()
	tests := []struct {
		name       string
		signals    Signals
		brand      string
		model      string
		deviceType string
		osFamily   string
	}{
		{name: "Windows", signals: Signals{Hints: []string{"Windows NT explicit device field"}}, brand: "Microsoft", deviceType: "desktop", osFamily: "Windows"},
		{name: "Android exact model", signals: Signals{Hostnames: []string{"MI9SE-campus"}}, brand: "Xiaomi", model: "Mi 9 SE", deviceType: "mobile", osFamily: "Android"},
		{name: "iOS", signals: Signals{Hostnames: []string{"iPhone-campus"}}, brand: "Apple", deviceType: "mobile", osFamily: "iOS"},
		{name: "Mac mini discovery name", signals: Signals{Hints: []string{"刘璐的mac mini"}}, brand: "Apple", model: "Mac mini", deviceType: "desktop", osFamily: "macOS"},
		{name: "Mac mini M4 hostname", signals: Signals{Hostnames: []string{"Mac-mini-M4"}}, brand: "Apple", model: "Mac mini M4", deviceType: "desktop", osFamily: "macOS"},
		{name: "printer", signals: Signals{DHCPVendorClass: "Hewlett-Packard JetDirect", Hints: []string{"Hewlett-Packard JetDirect"}}, brand: "HP", deviceType: "printer"},
		{name: "unknown", signals: Signals{MAC: "12:34:56:78:9a:bc", Hostnames: []string{"campus-device"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := library.IdentifySignals(test.signals)
			if result.Brand != test.brand || result.Model != test.model || result.DeviceType != test.deviceType || result.OSFamily != test.osFamily {
				t.Fatalf("unexpected recognition: %+v", result)
			}
		})
	}
}

func TestMacMiniRuleDoesNotPromoteGenericMacLabel(t *testing.T) {
	result := Default().IdentifySignals(Signals{Hostnames: []string{"Mac"}})
	if result.Brand != "" || result.Model != "" || result.DeviceType != "" || result.OSFamily != "" {
		t.Fatalf("generic Mac label must not identify a physical model: %+v", result)
	}
}

func TestIEEEPrefixLengthsAndSignalConflict(t *testing.T) {
	oui := []byte("Assignment,Organization Name\n001122,MA-L Vendor\nA8BBCCD,MA-M Vendor\n143456789,MA-S Vendor\n")
	fingerbank := []byte(`[{"requested_options":"1,3,6","device_type":"desktop","os_family":"Windows","description":"Windows DHCP","confidence":0.9}]`)
	library, err := LoadWithData("prefix-test", oui, embeddedRules, fingerbank, embeddedBrandAliases)
	if err != nil {
		t.Fatal(err)
	}
	for mac, vendor := range map[string]string{"00:11:22:aa:bb:cc": "MA-L Vendor", "a8:bb:cc:d1:23:45": "MA-M Vendor", "14:34:56:78:9a:bc": "MA-S Vendor"} {
		result := library.Identify(mac)
		if result.Vendor != vendor {
			t.Fatalf("MAC %s: expected %q, got %+v", mac, vendor, result)
		}
	}
	if result := library.Identify("10:34:56:78:9a:bc"); result.Vendor != "" {
		t.Fatalf("unregistered prefix must remain unknown: %+v", result)
	}
	result := library.IdentifySignals(Signals{UserAgents: []string{"iPhone"}, DHCPRequestedOptions: "1,3,6"})
	if result.Conflict || result.OSFamily != "Windows" || result.Brand != "" || result.Model != "" {
		t.Fatalf("UA must not override independent DHCP evidence: %+v", result)
	}
}

func TestUserAgentCannotPopulatePhysicalDeviceProfile(t *testing.T) {
	for _, ua := range []string{"MicroMessenger Client", "Mozilla/5.0 (iPhone)", "Mozilla/5.0 (Windows NT 10.0)", "Go-http-client/1.1"} {
		result := Default().IdentifySignals(Signals{UserAgents: []string{ua}})
		if result.Brand != "" || result.Model != "" || result.DeviceType != "" || result.OSFamily != "" || result.Confidence != 0 {
			t.Fatalf("UA %q must remain client metadata only: %+v", ua, result)
		}
	}
}

func TestRandomizedMACDoesNotUseOUI(t *testing.T) {
	library := MustLoad("test", []byte("Assignment,Organization Name\nE6C400,Example Vendor\n"), embeddedRules)
	result := library.Identify("e6:c4:00:00:00:01")
	if result.Vendor != "" || !result.RandomizedMAC {
		t.Fatalf("randomized MAC must not resolve vendor: %+v", result)
	}
}

func TestDarwinMacOSClueRequiresDHCPAndMacHostname(t *testing.T) {
	for _, c := range []struct {
		name    string
		signals Signals
		want    string
	}{
		{"combined", Signals{DHCPVendorClass: "darwin", Hostnames: []string{"office-mac41.local"}}, "macOS"},
		{"MacBook", Signals{DHCPVendorClass: "Darwin", Hostnames: []string{"Alice-MacBook-Pro.local"}}, "macOS"},
		{"vendor alone", Signals{DHCPVendorClass: "darwin"}, ""},
		{"hostname alone", Signals{Hostnames: []string{"office-mac41.local"}}, ""},
		{"iPhone", Signals{DHCPVendorClass: "darwin", Hostnames: []string{"campus-client"}}, ""},
		{"substring", Signals{DHCPVendorClass: "darwin", Hostnames: []string{"machine41.local"}}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Default().IdentifySignals(c.signals)
			if got.OSFamily != c.want || got.Brand != "" || got.Model != "" {
				t.Fatalf("unexpected recognition: %+v", got)
			}
			if c.want != "" && (got.OSFamilyConfidence >= .8 || len(got.Evidence) == 0) {
				t.Fatalf("must retain inference confidence and evidence: %+v", got)
			}
		})
	}
}
