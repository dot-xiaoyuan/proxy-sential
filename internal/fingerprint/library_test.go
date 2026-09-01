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
		{name: "Windows", signals: Signals{UserAgents: []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}}, brand: "Microsoft", deviceType: "desktop", osFamily: "Windows"},
		{name: "Android exact model", signals: Signals{Hostnames: []string{"MI9SE-campus"}}, brand: "Xiaomi", model: "Mi 9 SE", deviceType: "mobile", osFamily: "Android"},
		{name: "iOS", signals: Signals{UserAgents: []string{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)"}}, brand: "Apple", deviceType: "mobile", osFamily: "iOS"},
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
	conflict := library.IdentifySignals(Signals{UserAgents: []string{"iPhone"}, DHCPRequestedOptions: "1,3,6"})
	if !conflict.Conflict || conflict.OSFamily != "iOS" {
		t.Fatalf("conflicting DHCP evidence must not override high confidence UA: %+v", conflict)
	}
}

func TestRandomizedMACDoesNotUseOUI(t *testing.T) {
	library := MustLoad("test", []byte("Assignment,Organization Name\nE6C400,Example Vendor\n"), embeddedRules)
	result := library.Identify("e6:c4:00:00:00:01")
	if result.Vendor != "" || !result.RandomizedMAC {
		t.Fatalf("randomized MAC must not resolve vendor: %+v", result)
	}
}
