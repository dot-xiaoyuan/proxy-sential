package evidence

import "testing"

func TestPortableDHCPProfileIsNotADeviceFamily(t *testing.T) {
	for _, client := range []string{"dhcpcd-16", "udhcpc-1.36", "dhclient/4.4"} {
		if got := deviceFamily(map[string]any{"vendor_class": client, "device_hint": "linux", "hostname": "fixture-phone"}); got != "unknown" {
			t.Errorf("generic %s became %s", client, got)
		}
	}
	if got := deviceFamily(map[string]any{"vendor_class": "dhcpcd-16", "hostname": "android-phone"}); got != "android" {
		t.Fatalf("independent explicit clue lost: %s", got)
	}
}
