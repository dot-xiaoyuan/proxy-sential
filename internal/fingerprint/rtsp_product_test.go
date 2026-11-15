package fingerprint

import (
	"testing"
	"time"
)

func TestRTSPExplicitRecorderHasTypeWithoutInventedModel(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct{ protocol, field, value, direction, want string }{
		{"rtsp", "rtsp_user_agent", "HIKVISION player NVR V4.74.210", "client", "recorder"},
		{"rtsp", "rtsp_user_agent", "HIKVISION player NVR V4.84.030", "client", "recorder"},
		{"rtsp", "rtsp_user_agent", "HIKVISION player NVR V4.74.210", "server", ""},
		{"http", "rtsp_user_agent", "HIKVISION player NVR V4.74.210", "client", ""},
		{"rtsp", "rtsp_user_agent", "HIKVISION player", "client", ""},
		{"rtsp", "rtsp_user_agent", "VLC HIKVISION player NVR V4.74.210", "client", ""},
		{"rtsp", "rtsp_user_agent", "HIKVISION player NVR V4.74.210 ffmpeg", "client", ""},
	} {
		s := hardwareSignal(tc.protocol, tc.field, tc.value, "rtsp-product")
		s.Direction = tc.direction
		r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s}}, now)
		if r.Type != tc.want || r.Model != "" {
			t.Fatalf("%+v: %+v", tc, r)
		}
		if tc.want != "" && r.Manufacturer != "Hikvision" {
			t.Fatalf("self-reported brand lost: %+v", r)
		}
		if r := EvaluateHardware(HardwareInput{Evidence: []EvidenceSignal{s}}, now); r.Type != "" {
			t.Fatal("unowned recorder UA became physical type")
		}
	}
}
