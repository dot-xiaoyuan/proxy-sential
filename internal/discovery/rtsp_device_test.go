package discovery

import "testing"

func TestRTSPDeviceIdentity(t *testing.T) {
	for _, tc := range []struct {
		value, kind, brand string
	}{
		{"HIKVISION player NVR V4.84.030", "recorder", "Hikvision"},
		{"Dahua NVR", "recorder", "Dahua"},
		{"Hikvision", "camera", "Hikvision"},
		{"AXIS Camera", "camera", "Axis"},
		{"VLC/3.0.20 LibVLC/3.0.20", "", ""},
		{"ffmpeg", "", ""},
	} {
		kind, brand, _ := RTSPDeviceIdentity(tc.value)
		if kind != tc.kind || brand != tc.brand {
			t.Fatalf("%q => %q %q", tc.value, kind, brand)
		}
	}
}
