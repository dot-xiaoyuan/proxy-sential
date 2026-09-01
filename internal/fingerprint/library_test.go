package fingerprint

import "testing"

func TestIdentifyOUIAndDeviceRule(t *testing.T) {
	library := Default()
	vmware := library.Identify("00:0c:29:aa:bb:cc")
	if vmware.Vendor != "VMware, Inc." || vmware.Brand != "VMware" {
		t.Fatalf("unexpected VMware identification: %+v", vmware)
	}
	if vmware.VendorConfidence != .9 || vmware.BrandConfidence < .8 || vmware.ModelConfidence != 0 {
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

func TestRandomizedMACDoesNotUseOUI(t *testing.T) {
	library := MustLoad("test", []byte("Assignment,Organization Name\nE6C400,Example Vendor\n"), embeddedRules)
	result := library.Identify("e6:c4:00:00:00:01")
	if result.Vendor != "" || !result.RandomizedMAC {
		t.Fatalf("randomized MAC must not resolve vendor: %+v", result)
	}
}
