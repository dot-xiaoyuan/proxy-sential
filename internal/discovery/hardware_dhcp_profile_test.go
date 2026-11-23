package discovery

import (
	"strings"
	"testing"
	"time"
)

func TestDHCPManufacturerModelRequiresMatchingOriginalLease(t *testing.T) {
	at := time.Now().UTC()
	for _, tc := range []struct {
		name, vendor, host, messages, want string
		withRef                            bool
	}{
		{"phone", "HUAWEI:openharmony:SGT-AL50", "SGT-AL50", "REQUEST,ACK", "mobile", true},
		{"tablet", "HUAWEI:openharmony:SLG-W50", "SLG-W50", "REQUEST,ACK", "tablet", true},
		{"short platform", "HUAWEI:android:SGT", "SGT-AL50", "REQUEST,ACK", "", true},
		{"different model", "HUAWEI:openharmony:SGT-AL10", "SGT-AL50", "REQUEST,ACK", "", true},
		{"server only", "HUAWEI:openharmony:SGT-AL50", "SGT-AL50", "ACK", "", true},
		{"release", "HUAWEI:openharmony:SGT-AL50", "SGT-AL50", "REQUEST,ACK,RELEASE", "", true},
		{"missing file", "HUAWEI:openharmony:SGT-AL50", "SGT-AL50", "REQUEST,ACK", "", false},
		{"unreviewed", "HUAWEI:openharmony:ZZZ-AL00", "ZZZ-AL00", "REQUEST,ACK", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := hardwareTestObservation(at)
			o.Origin = "dhcp"
			o.Evidence.Source = "zeek"
			o.Evidence.Payload = map[string]any{"msg_types": tc.messages, "assigned_addr": o.IP, "dhcp_product_vendor_class": tc.vendor, "hostname": tc.host, "mac": o.MAC, "dhcp_capture_vlan": o.VLAN}
			o.Evidence.RawRef = nil
			if tc.withRef {
				o.Evidence.RawRef = map[string]any{"content_sha256": strings.Repeat("b", 64), "ingest_source_ref": map[string]any{"file_id": "original-file"}}
			}
			f, err := HardwareFactFromObservation(o)
			if err != nil || f == nil {
				t.Fatalf("fact=%+v err=%v", f, err)
			}
			s, err := EvaluateHardwareFacts([]HardwareFact{*f}, nil, at)
			if err != nil || s.HardwareType != "" || s.HardwareModel != "" || DHCPLeaseCandidateType(o) != tc.want {
				t.Fatalf("confirmed %s/%s, candidate %q, expected clue %q, error=%v", s.HardwareType, s.HardwareModel, DHCPLeaseCandidateType(o), tc.want, err)
			}
		})
	}
}

func TestSADPCameraRequiresPayloadDigest(t *testing.T) {
	at := time.Now().UTC()
	for _, tc := range []struct{ model, digest, want string }{
		{"DS-IPC-B12-I", strings.Repeat("c", 64), "camera"}, {"DS-IPC-B12-I", "", ""}, {"DS-IPC-B12-I2", strings.Repeat("c", 64), ""},
	} {
		o := hardwareTestObservation(at)
		o.Evidence.Payload["product_model"] = tc.model
		o.Evidence.RawRef = map[string]any{"payload_sha256": tc.digest}
		f, err := HardwareFactFromObservation(o)
		if err != nil || f == nil {
			t.Fatalf("fact=%+v err=%v", f, err)
		}
		s, err := EvaluateHardwareFacts([]HardwareFact{*f}, nil, at)
		if err != nil || s.HardwareType != tc.want {
			t.Fatalf("model %q ref %q got %q, err=%v", tc.model, tc.digest, s.HardwareType, err)
		}
	}
}

func TestDHCPCloudSwitchModelNeedsScopedHardwareSuffix(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct{ mac, host, vendor, want string }{
		{"74:3a:20:10:00:d5", "S24G-U_00D5", "CloudSwitch_1", "switch"},
		{"74:3a:20:10:00:d5", "S24G-U_00D6", "CloudSwitch_1", ""},
		{"02:00:00:10:00:d5", "S24G-U_00D5", "CloudSwitch_1", ""},
		{"74:3a:20:10:00:d5", "S24G-U_00D5", "generic", ""},
	} {
		o := hardwareTestObservation(now)
		o.Origin = "dhcp"
		o.MAC = tc.mac
		o.Evidence.Source = "zeek"
		o.Evidence.RawRef = map[string]any{"content_sha256": strings.Repeat("a", 64), "original_file_id": "binding-file"}
		o.Evidence.Payload = map[string]any{"msg_types": "REQUEST,ACK", "assigned_addr": o.IP, "mac": o.MAC, "dhcp_capture_vlan": o.VLAN, "hostname": tc.host, "dhcp_product_vendor_class": tc.vendor}
		f, err := HardwareFactFromObservation(o)
		if err != nil || f == nil {
			t.Fatalf("fact: %v / %v", f, err)
		}
		s, err := EvaluateHardwareFacts([]HardwareFact{*f}, nil, now)
		if err != nil || s.HardwareType != tc.want {
			t.Fatalf("%+v got %s err %v", tc, s.HardwareType, err)
		}
	}
}

func TestInfrastructureLeaseProductFields(t *testing.T) {
	at := time.Now().UTC()
	for _, tc := range []struct{ option, host, mac, want string }{
		{"huawei AP", "Huawei AP-AirEngine5762-10-28:41:ec:00:00:01", "28:41:ec:00:00:01", "AirEngine 5762-10"},
		{"huawei AP", "Huawei AP-AirEngine5762-10-28:41:ec:00:00:02", "28:41:ec:00:00:01", ""},
		{"YLS220-24G2F", "YLS220-24G2F", "78:60:5b:00:00:01", "YLS220-24G2F"},
		{"YLS220-24G2F", "YLS220-24G2F", "02:00:5b:00:00:01", ""},
		{"TL-SG2008D", "", "9c:47:82:00:00:01", "TL-SG2008D"},
		{"TL-SG2008DE", "", "9c:47:82:00:00:01", ""},
		{"H3C NX30", "H3C_NX30", "70:c6:dd:00:00:01", "NX30"},
		{"H3C NX30", "H3C_NX30 Pro", "70:c6:dd:00:00:01", ""},
	} {
		o := hardwareTestObservation(at)
		o.Origin = "dhcp"
		o.MAC = tc.mac
		o.Evidence.Source = "zeek"
		o.Evidence.RawRef = map[string]any{"content_sha256": strings.Repeat("a", 64), "original_file_id": "lease-file"}
		o.Evidence.Payload = map[string]any{"msg_types": "REQUEST,ACK", "assigned_addr": o.IP, "mac": o.MAC, "dhcp_capture_vlan": o.VLAN, "hostname": tc.host, "dhcp_product_vendor_class": tc.option}
		f, err := HardwareFactFromObservation(o)
		if err != nil || f == nil {
			t.Fatalf("fact %v error %v", f, err)
		}
		s, err := EvaluateHardwareFacts([]HardwareFact{*f}, nil, at)
		if err != nil || s.HardwareModel != tc.want {
			t.Fatalf("%+v model=%q err=%v", tc, s.HardwareModel, err)
		}
	}
}
