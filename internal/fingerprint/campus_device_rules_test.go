package fingerprint

import "testing"

// Hostnames and vendor classes follow values observed on the 184 campus
// mirror (2026-10-12); hex suffixes are synthetic.
func TestCampusSelfReportedDeviceRules(t *testing.T) {
	cases := []struct {
		name                     string
		signals                  Signals
		deviceType, brand, model string
		osFamily                 string
	}{
		{"tp-link router with windows vendor class", Signals{Hostnames: []string{"TL-WDR7666千兆易展版"}, DHCPVendorClass: "MSFT 5.0", Hints: []string{"windows"}}, "router", "TP-Link", "TL-WDR7666", ""},
		{"tp-link legacy router", Signals{Hostnames: []string{"TL-WR842N"}}, "router", "TP-Link", "TL-WR842N", ""},
		{"xiaomi router", Signals{Hostnames: []string{"MiWiFi-R4AV2"}, DHCPVendorClass: "udhcp 1.25.1"}, "router", "Xiaomi", "MiWiFi R4AV2", ""},
		{"tp-link switch is not a router", Signals{DHCPVendorClass: "TL-SG5428"}, "switch", "TP-Link", "", ""},
		{"huawei campus AP", Signals{Hostnames: []string{"Huawei AP-AirEngine5762-13HW-ac:12:34:56:78:9a"}, DHCPVendorClass: "huawei AP"}, "access_point", "Huawei", "AirEngine5762-13HW", ""},
		{"h3c switch", Signals{DHCPVendorClass: "H3C. H3C S5130S-28P-HPWR-EI-AC"}, "switch", "H3C", "S5130S-28P-HPWR-EI-AC", ""},
		{"hp printer vendor class", Signals{DHCPVendorClass: "HP LaserJet"}, "printer", "HP", "", ""},
		{"hp printer factory hostname", Signals{Hostnames: []string{"NPI8A2B3C"}}, "printer", "HP", "", ""},
		{"xiaomi camera", Signals{Hostnames: []string{"chuangmi.camera.029a02"}, DHCPVendorClass: "udhcp 1.28.1"}, "camera", "Xiaomi", "智能摄像机", ""},
		{"xiaomi tv", Signals{Hostnames: []string{"MITV"}}, "media_device", "Xiaomi", "小米电视", ""},
		{"midea air conditioner", Signals{Hostnames: []string{"midea_ac_0b2f"}}, "iot", "Midea", "美的家电(ac)", ""},
		{"youdao dictionary pen", Signals{Hostnames: []string{"YoudaoDictionaryPen-435"}, DHCPVendorClass: "udhcp 1.34.1"}, "iot", "Youdao", "有道词典笔", ""},
		{"alpha egg pen vendor class", Signals{DHCPVendorClass: "Alpha Egg:Smart Pen:TYS01"}, "iot", "iFlytek", "阿尔法蛋词典笔", ""},
		{"huawei harmony tablet", Signals{DHCPVendorClass: "HUAWEI:openharmony:SLG-W50"}, "tablet", "Huawei", "SLG-W50", "HarmonyOS"},
		{"huawei harmony phone", Signals{DHCPVendorClass: "HUAWEI:openharmony:ALN-AL00"}, "mobile", "Huawei", "ALN-AL00", "HarmonyOS"},
		{"honor pinyin tablet", Signals{Hostnames: []string{"rong-yao-ping-banV8-Pro"}}, "tablet", "Honor", "", ""},
		{"honor pinyin phone", Signals{Hostnames: []string{"rong-yaoMagic6"}}, "mobile", "Honor", "", ""},
		{"busybox client is platform only", Signals{DHCPVendorClass: "udhcp 1.19.4"}, "", "", "", "Embedded Linux"},
		{"arm dhcpcd is not a desktop", Signals{DHCPVendorClass: "dhcpcd-9.4.1:Linux-5.10.160:armv7l:Rockchip"}, "", "", "", "Embedded Linux"},
		{"generic android unchanged", Signals{Hostnames: []string{"vivo-S19"}, DHCPVendorClass: "android-dhcp-15", Hints: []string{"android"}}, "mobile", "", "", "Android"},
	}
	for _, tc := range cases {
		got := Default().IdentifySignals(tc.signals)
		if got.DeviceType != tc.deviceType || got.Brand != tc.brand || got.Model != tc.model || got.OSFamily != tc.osFamily {
			t.Errorf("%s: got type=%q brand=%q model=%q os=%q, want %q %q %q %q", tc.name, got.DeviceType, got.Brand, got.Model, got.OSFamily, tc.deviceType, tc.brand, tc.model, tc.osFamily)
		}
		if tc.deviceType != "" && got.DeviceTypeConfidence < .8 {
			t.Errorf("%s: device type confidence %.2f is below the UI display threshold", tc.name, got.DeviceTypeConfidence)
		}
	}
}

func TestCampusRulesDoNotClassifyPhonesAsDumbTerminals(t *testing.T) {
	for _, hostname := range []string{"Redmi-K70", "xiaomi-14", "OPPO-Reno12", "iQOO-Neo9", "HUAWEI_Mate_60_Pro_(UD)-1", "DESKTOP-8KQ2M1L", "admin", "liu"} {
		got := Default().IdentifySignals(Signals{Hostnames: []string{hostname}})
		switch got.DeviceType {
		case "router", "switch", "access_point", "printer", "camera", "media_device", "iot":
			t.Errorf("%s classified as %s", hostname, got.DeviceType)
		}
	}
}
