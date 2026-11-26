package fingerprint

import "testing"

func TestPhase2CampusDHCPAndHarmonyRules(t *testing.T) {
	lib := Default()

	t.Run("DHCP Option 138 CAPWAP AP 识别无线接入点", func(t *testing.T) {
		res := lib.IdentifySignals(Signals{
			MAC:                  "02:00:00:aa:bb:01",
			DHCPRequestedOptions: "1,3,6,138,52,43,15,42,67,150",
		})
		if res.DeviceType != "access_point" {
			t.Fatalf("expected access_point from Option 138, got %+v", res)
		}
	})

	t.Run("华为鸿蒙 DHCP Vendor Class 不依赖主机名识别品牌、系统与类型", func(t *testing.T) {
		res := lib.IdentifySignals(Signals{
			MAC:             "02:00:00:aa:bb:02",
			DHCPVendorClass: "HUAWEI:openharmony:SGT-AL10",
			Hostnames:       []string{"UserRenamedPhone"},
		})
		if res.Brand != "Huawei" || res.OSFamily != "HarmonyOS" || res.DeviceType != "mobile" {
			t.Fatalf("expected Huawei/HarmonyOS/mobile, got brand=%q os=%q type=%q", res.Brand, res.OSFamily, res.DeviceType)
		}
	})

	t.Run("新版 dhcpcd-16 识别为 Android 且不误伤嵌入式 Linux dhcpcd", func(t *testing.T) {
		android := lib.IdentifySignals(Signals{
			MAC:             "02:00:00:aa:bb:03",
			DHCPVendorClass: "dhcpcd-16",
		})
		if android.OSFamily != "Android" {
			t.Fatalf("expected Android for dhcpcd-16, got %q", android.OSFamily)
		}
		embedded := lib.IdentifySignals(Signals{
			MAC:             "02:00:00:aa:bb:04",
			DHCPVendorClass: "dhcpcd-9.4.1:Linux-5.10.160:armv7l:Rockchip",
		})
		if embedded.OSFamily == "Android" {
			t.Fatalf("embedded linux dhcpcd must not be classified as Android: %+v", embedded)
		}
	})
}
