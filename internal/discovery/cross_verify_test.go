package discovery

import "testing"

func TestEvaluateCrossVerification(t *testing.T) {
	t.Run("DHCP Option 138 与 CAPWAP 端口互证无线接入点", func(t *testing.T) {
		res := EvaluateCrossVerification(CrossVerificationInput{
			DHCPRequestedOptions:  "1,3,6,138,52,43,15,42,67,150",
			ObservedResponsePorts: []string{"udp/5246"},
		})
		if res.Status != "cross_verified" || res.DeviceType != "access_point" || len(res.IndependentSources) < 2 {
			t.Fatalf("expected cross_verified access_point, got %+v", res)
		}
	})

	t.Run("海康厂商线索与 8000 响应端口互证摄像机", func(t *testing.T) {
		res := EvaluateCrossVerification(CrossVerificationInput{
			Vendor:                "Hangzhou Hikvision Digital Technology Co.,Ltd.",
			ObservedResponsePorts: []string{"tcp/8000"},
		})
		if res.Status != "cross_verified" || res.DeviceType != "camera" {
			t.Fatalf("expected cross_verified camera, got %+v", res)
		}
	})

	t.Run("单源信号不得升级为交叉确认", func(t *testing.T) {
		res := EvaluateCrossVerification(CrossVerificationInput{
			DHCPVendorClass: "MSFT 5.0",
		})
		if res.Status != "" || res.DeviceType != "" {
			t.Fatalf("single source should not cross-verify, got %+v", res)
		}
	})

	t.Run("Windows DHCP 与系统遥测 SNI 互证个人电脑", func(t *testing.T) {
		res := EvaluateCrossVerification(CrossVerificationInput{
			DHCPVendorClass: "MSFT 5.0",
			SNIEcosystems:   []string{"Windows"},
		})
		if res.Status != "cross_verified" || res.DeviceType != "desktop" {
			t.Fatalf("expected cross_verified desktop, got %+v", res)
		}
	})

	t.Run("华为鸿蒙 DHCP 与华为连通性 SNI 互证移动终端", func(t *testing.T) {
		res := EvaluateCrossVerification(CrossVerificationInput{
			DHCPVendorClass: "HUAWEI:openharmony:SGT-AL10",
			SNIBrandHint:    "Huawei",
		})
		if res.Status != "cross_verified" || res.DeviceType != "mobile" {
			t.Fatalf("expected cross_verified mobile, got %+v", res)
		}
	})

	t.Run("互斥品类同时命中时返回 conflict 绝不强行取胜", func(t *testing.T) {
		res := EvaluateCrossVerification(CrossVerificationInput{
			Vendor:                "Hikvision HP",
			ObservedResponsePorts: []string{"tcp/8000", "tcp/9100"},
		})
		if res.Status != "conflict" || res.DeviceType != "" || len(res.ConflictingTypes) != 2 {
			t.Fatalf("expected conflict for camera+printer, got %+v", res)
		}
	})
}

func TestIsL3ManagedEntity(t *testing.T) {
	managed := DeviceView{
		Addresses: []string{"10.131.253.1"},
		ProductClues: []IPProductClue{
			{IP: "10.131.253.1", Type: "switch", Manufacturer: "H3C", Model: "E528C-PWR", ProductStatus: "identified", Attribution: "response_ip"},
		},
	}
	if !IsL3ManagedEntity(managed) || deviceIdentityKind(managed) != "l3_managed_entity" {
		t.Fatalf("expected l3_managed_entity, got %q", deviceIdentityKind(managed))
	}

	withMAC := managed
	withMAC.MAC = "aa:bb:cc:dd:ee:01"
	if IsL3ManagedEntity(withMAC) || deviceIdentityKind(withMAC) != "network_address" {
		t.Fatalf("MAC device should stay network_address, got %q", deviceIdentityKind(withMAC))
	}

	unidentified := DeviceView{
		Addresses: []string{"10.131.253.2"},
		ProductClues: []IPProductClue{
			{IP: "10.131.253.2", ProductStatus: "no_type_match", Attribution: "response_ip"},
		},
	}
	if IsL3ManagedEntity(unidentified) || deviceIdentityKind(unidentified) != "network_address" {
		t.Fatalf("unidentified IP clue should stay network_address, got %q", deviceIdentityKind(unidentified))
	}
}
