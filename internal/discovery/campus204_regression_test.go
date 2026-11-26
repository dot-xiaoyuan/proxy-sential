package discovery

import (
	"strings"
	"testing"
	"time"
)

// TestCampus204PassiveDiscoveryRegression 固化 204 校园网被动资产发现（阶段一至五）脱敏回归基线，
// 覆盖纯二层 IEEE 1905 心跳、DHCP 移动端/Option 138 AP 指纹、LAA 随机 MAC 多源交叉确认、
// CAPWAP 与大华跨三层 IP 产品线索、SSH 服务端 Banner 指纹及特征摸底报告有界渲染。
func TestCampus204PassiveDiscoveryRegression(t *testing.T) {
	now := time.Now().UTC()

	t.Run("IEEE1905纯二层心跳允许刷新活跃但不制造硬件类型", func(t *testing.T) {
		obs := hardwareTestObservation(now.Add(-time.Minute))
		obs.Origin = "ieee1905"
		obs.IP = ""
		obs.MAC = "10:5d:dc:9b:13:b1"
		obs.Evidence.Subject = map[string]any{"mac": obs.MAC}
		obs.Evidence.Payload = map[string]any{}

		fact, err := HardwareFactFromObservation(obs)
		if err != nil {
			t.Fatalf("unexpected error for ieee1905 heartbeat: %v", err)
		}
		if fact == nil || !fact.AddressOnly || fact.MAC != obs.MAC {
			t.Fatalf("expected AddressOnly heartbeat fact for ieee1905, got %+v", fact)
		}
		if len(fact.Signals) != 0 {
			t.Fatalf("ieee1905 heartbeat must not inject hardware type signals: %+v", fact.Signals)
		}
	})

	t.Run("DHCP_Option138与哑终端候选指纹覆盖", func(t *testing.T) {
		if got := PassiveDHCPClientCandidate("", "", "1,3,6,15,43,66,138"); got != "access_point" {
			t.Fatalf("expected RFC 5417 Option 138 + 43/66 to yield access_point, got %q", got)
		}
		if got := PassiveDHCPClientCandidate("MSFT 5.0", "", "1,3,6,15,43,66,138"); got == "access_point" {
			t.Fatalf("expected Windows client requesting Option 138 not to be misclassified as access_point")
		}
		if got := PassiveDHCPClientCandidate("HP LaserJet M404", "NPI123456", "1,3,6,15"); got != "printer" {
			t.Fatalf("expected HP LaserJet DHCP to yield printer, got %q", got)
		}
		if got := PassiveDHCPClientCandidate("Yealink SIP-T46S", "SIP-T46S", "1,3,6,15"); got != "voip_phone" {
			t.Fatalf("expected Yealink DHCP to yield voip_phone, got %q", got)
		}
	})

	t.Run("LAA随机MAC多源交叉确认与冲突保护", func(t *testing.T) {
		cases := []struct {
			name     string
			in       CrossVerificationInput
			wantStat string
			wantType string
			wantRule string
		}{
			{
				name: "华为鸿蒙随机MAC_DHCP与生态SNI互证",
				in: CrossVerificationInput{
					DHCPVendorClass: "HUAWEI:openharmony:ALN-AL00",
					SNIEcosystems:   []string{"Huawei"},
				},
				wantStat: "cross_verified",
				wantType: "mobile",
				wantRule: "cross:mobile-dhcp-ecosystem",
			},
			{
				name: "小米安卓随机MAC_DHCP与小米生态SNI互证",
				in: CrossVerificationInput{
					DHCPVendorClass: "android-dhcp-14",
					SNIEcosystems:   []string{"Xiaomi"},
				},
				wantStat: "cross_verified",
				wantType: "mobile",
				wantRule: "cross:mobile-dhcp-ecosystem",
			},
			{
				name: "Apple_iOS随机MAC_Opt55与Apple生态互证",
				in: CrossVerificationInput{
					DHCPRequestedOptions: "1,121,3,6,15,108,114,119,252",
					SNIEcosystems:        []string{"Apple"},
				},
				wantStat: "cross_verified",
				wantType: "mobile",
				wantRule: "cross:mobile-apple-dhcp55-ecosystem",
			},
			{
				name: "Windows桌面终端_MSFT与系统UA互证",
				in: CrossVerificationInput{
					DHCPVendorClass: "MSFT 5.0",
					UserAgents:      []string{"Microsoft NCSI"},
				},
				wantStat: "cross_verified",
				wantType: "desktop",
				wantRule: "cross:desktop-windows-dhcp-telemetry",
			},
			{
				name: "互斥品类信号冲突时拒绝强行确认",
				in: CrossVerificationInput{
					DHCPVendorClass:       "MSFT 5.0",
					UserAgents:            []string{"Microsoft NCSI"},
					Vendor:                "Hikvision",
					ObservedResponsePorts: []string{"tcp/8000"},
				},
				wantStat: "conflict",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := EvaluateCrossVerification(tc.in)
				if got.Status != tc.wantStat || got.DeviceType != tc.wantType {
					t.Fatalf("unexpected cross verification: got=%+v want status=%q type=%q", got, tc.wantStat, tc.wantType)
				}
				if tc.wantRule != "" && got.RuleID != tc.wantRule {
					t.Fatalf("unexpected rule_id: got=%q want=%q", got.RuleID, tc.wantRule)
				}
			})
		}
	})

	t.Run("跨三层CAPWAP与大华发现生成受管网元产品线索且不捏造物理MAC", func(t *testing.T) {
		sha := "30199b1a7eac0d6ca46a350da50521e4e8786b460b75e4c798f5f4f040508178"
		ap := hardwareTestObservation(now.Add(-time.Minute))
		ap.Origin, ap.MAC, ap.IP = "capwap", "", "10.152.11.95"
		ap.DeviceType, ap.Manufacturer = "access_point", "Huawei"
		ap.Evidence.Flow = map[string]any{"src_ip": ap.IP, "dst_ip": "10.126.1.10"}
		ap.Evidence.Payload = map[string]any{
			"is_request":     true,
			"message_type":   "data_keepalive",
			"manufacturer":   "Huawei",
			"payload_sha256": sha,
		}
		clue, err := BuildIPProductClue(ap, now)
		if err != nil || clue == nil || clue.Type != "access_point" || clue.ProductStatus != "identified" || clue.Attribution != "request_ip" {
			t.Fatalf("expected CAPWAP keepalive IP product clue, got clue=%+v err=%v", clue, err)
		}
		if fact, err := HardwareFactFromObservation(ap); err != nil || fact != nil {
			t.Fatalf("cross-L3 CAPWAP must not fabricate physical MAC fact: %+v err=%v", fact, err)
		}
		if !IsL3ManagedEntity(DeviceView{Addresses: []string{ap.IP}, ProductClues: []IPProductClue{*clue}}) {
			t.Fatalf("expected CAPWAP IP product clue to classify as l3_managed_entity")
		}
		if IsL3ManagedEntity(DeviceView{Addresses: []string{"10.152.11.96"}}) {
			t.Fatalf("plain address clue without verified product_clue must not be l3_managed_entity")
		}
	})

	t.Run("SSH服务端Banner指纹识别边界", func(t *testing.T) {
		if kind, brand, osHint := SSHBannerIdentity("SSH-2.0-dropbear_2022.83"); kind != "" || brand != "" || osHint != "Embedded Linux" {
			t.Fatalf("expected dropbear banner to emit Embedded Linux OS hint without guessing hardware, got kind=%q brand=%q os=%q", kind, brand, osHint)
		}
		if kind, brand, osHint := SSHBannerIdentity("SSH-2.0-Comware-7.1.070"); kind != "switch" || brand != "H3C" || osHint != "Comware" {
			t.Fatalf("expected H3C Comware SSH banner recognition, got kind=%q brand=%q os=%q", kind, brand, osHint)
		}
		if kind, brand, _ := SSHBannerIdentity("SSH-2.0-Cisco-1.25"); brand != "Cisco" || kind != "router" {
			t.Fatalf("expected Cisco SSH banner recognition, got kind=%q brand=%q", kind, brand)
		}
		if kind, brand, osHint := SSHBannerIdentity("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"); osHint == "" || brand != "" || kind != "" {
			// 通用 OpenSSH 仅输出 OS 线索，不应冒充硬件品类或厂商
			t.Fatalf("unexpected OpenSSH Ubuntu identity: kind=%q brand=%q os=%q", kind, brand, osHint)
		}
	})

	t.Run("特征摸底报告完整渲染随机MAC占比与新协议命中", func(t *testing.T) {
		md := RenderGapReportMarkdown(GapReport{
			SensorID:    "campus-204",
			Window:      "24h0m0s",
			GeneratedAt: now.Format(time.RFC3339),
			Overlap:     TwoListOverlap{TerminalMACs: 4734, DiscoveryMACs: 4274, OverlapMACs: 4184, TerminalOnlyMACs: 550, DiscoveryOnlyMACs: 90},
			RandomMAC:   RandomMACStats{TotalMACs: 4274, LocalAdminMACs: 2896, GlobalMACs: 1378, LocalAdminRatio: 2896.0 / 4274.0},
			NewProtocolHits: []FeatureGapItem{
				{Category: "capwap", Value: "echo_request", Entities: 472, Events: 10616},
			},
		})
		for _, want := range []string{"67.8%", "随机 MAC（LAA）", "`echo_request`", "| 4734 | 4274 | 4184 | 550 | 90 |"} {
			if !strings.Contains(md, want) {
				t.Fatalf("gap report missing %q:\n%s", want, md)
			}
		}
	})
}
