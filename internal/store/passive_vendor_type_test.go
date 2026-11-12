package store

import "testing"

func TestGenericHikvisionBrandDoesNotProveCamera(t *testing.T) {
	for _, sample := range []struct {
		name, got string
	}{
		{"SNMP environmental monitor", snmpDeviceType("Hikvision environmental monitor")},
		{"SNMP access terminal", snmpDeviceType("Hikvision DS-K1T6QT-F72M")},
		{"HTTP access terminal", httpDeviceType("Hikvision", "Access Control")},
	} {
		if sample.got != "" {
			t.Errorf("%s classified as %q", sample.name, sample.got)
		}
	}
	if got := snmpDeviceType("Hikvision Network Camera"); got != "camera" {
		t.Fatalf("explicit camera description classified as %q", got)
	}
	if got := tlsCertDeviceType("CN=Hikvision", "Hikvision"); got != "" {
		t.Fatalf("vendor-only certificate classified as %q", got)
	}
	if got := tlsCertDeviceType("CN=Network Camera", "Hikvision"); got != "camera" {
		t.Fatalf("explicit camera certificate classified as %q", got)
	}
}
