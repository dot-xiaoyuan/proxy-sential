package fingerprint

import "testing"

// 覆盖常见消费级与企业级网络设备型号，防止新增规则过度匹配（如把网卡判成路由器）。
func TestRouterRulesRecognizeNetworkDevices(t *testing.T) {
	rules, err := LoadRouterRuleSet(EmbeddedRouterRules())
	if err != nil {
		t.Fatal(err)
	}
	routerCases := map[string]string{
		"Cisco ISR4331":             "Cisco",
		"Cisco ASR1001-X":           "Cisco",
		"Cisco Catalyst 9300":       "Cisco",
		"Cisco ASA5525-X":           "Cisco",
		"Juniper SRX345":            "Juniper",
		"Juniper EX4300":            "Juniper",
		"FortiGate 100F":            "Fortinet",
		"PA-220":                    "Palo Alto",
		"Aruba AP-515":              "Aruba",
		"UniFi UDM Pro":             "Ubiquiti",
		"EdgeRouter 4":              "Ubiquiti",
		"UAP-AC-Pro":                "Ubiquiti",
		"Archer AX55":               "TP-Link",
		"Archer C7":                 "TP-Link",
		"Archer BE800":              "TP-Link",
		"Deco X60":                  "TP-Link",
		"EAP245":                    "TP-Link",
		"TP-Link Omada ER605":       "TP-Link",
		"ZXHN F660":                 "ZTE",
		"ZXR10 5960":                "ZTE",
		"问天BE7200 Pro+":             "ZTE",
		"USG6300E":                  "Huawei",
		"CloudEngine S5731":         "Huawei",
		"RG-EG3230":                 "Ruijie",
		"RG-AP840-I":                "Ruijie",
		"RG-S5750":                  "Ruijie",
		"Vigor2926":                 "DrayTek",
		"RT2600ac":                  "Synology",
		"iKuai OS V4":               "iKuai",
		"pfSense 2.7":               "pfSense",
	}
	for input, wantBrand := range routerCases {
		got := ""
		for _, m := range rules.Match(map[string][]string{"hostname": {input}, "http_title": {input}}) {
			if !m.Rule.Exclude && m.Brand == wantBrand {
				got = m.Brand
			}
		}
		if got != wantBrand {
			t.Errorf("router %q: want brand %s, got match=%q", input, wantBrand, got)
		}
	}

	notRouter := []string{
		"TP-Link Archer TBE400E", "TP-Link Archer T3U", "TP-Link Archer TX20U",
		"TP-Link UE300", "TP-Link TG-3468", "TP-Link TL-WN823N",
		"iPhone14,5", "SM-G991B", "ESP32", "DiskStation DS920+",
		"Windows 10 Pro", "VMware ESXi 8", "Linux 5.15.0", "MacBookPro18,3",
	}
	for _, input := range notRouter {
		for _, m := range rules.Match(map[string][]string{"hostname": {input}, "software": {input}, "http_title": {input}}) {
			if m.Rule.Role == "router" && !m.Rule.Exclude {
				t.Errorf("non-router %q matched router rule %s (brand %s)", input, m.Rule.ID, m.Brand)
			}
		}
	}
}

func TestDeviceRulesRecognizeModelCodes(t *testing.T) {
	lib, err := Load(EmbeddedVersion, embeddedOUI, embeddedRules)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"iPhone14,5":            "Apple",
		"MacBookPro18,3":        "Apple",
		"SM-G991B":              "Samsung",
		"Pixel 7 Pro":           "Google",
		"ESP32-S3":              "Espressif",
		"DS-2CD2143G0-I":        "Hikvision",
		"IPC-HDW5442T-ZE":       "Dahua",
		"PS5":                   "Sony",
		"Raspberry Pi 4":        "Raspberry Pi",
	}
	for input, wantBrand := range cases {
		res := lib.Identify("", input)
		if res.Brand != wantBrand {
			t.Errorf("device %q: want brand %s, got %q (type %q)", input, wantBrand, res.Brand, res.DeviceType)
		}
	}
}
