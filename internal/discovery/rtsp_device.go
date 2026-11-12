package discovery

import "strings"

// RTSPDeviceIdentity classifies only explicit camera or recorder roles in an
// RTSP User-Agent or responder Server header. A vendor name alone is a clue.
func RTSPDeviceIdentity(values ...string) (deviceType, brand, model string) {
	text := strings.ToLower(strings.TrimSpace(strings.Join(values, " ")))
	if text == "" {
		return "", "", ""
	}
	for _, client := range []string{"vlc", "ffmpeg", "gstreamer", "live555", "quicktime", "lavf"} {
		if strings.Contains(text, client) {
			return "", "", ""
		}
	}
	recorder := strings.Contains(text, "nvr") || strings.Contains(text, "dvr")
	camera := strings.Contains(text, "camera")
	switch {
	case strings.Contains(text, "hikvision"):
		if recorder {
			return "recorder", "Hikvision", ""
		}
		if camera {
			return "camera", "Hikvision", ""
		}
	case strings.Contains(text, "dahua"):
		if recorder {
			return "recorder", "Dahua", ""
		}
		if camera {
			return "camera", "Dahua", ""
		}
	case strings.Contains(text, "uniview"):
		if camera {
			return "camera", "Uniview", ""
		}
	case strings.Contains(text, "axis"):
		if camera {
			return "camera", "Axis", ""
		}
	case strings.Contains(text, "reolink"):
		if camera {
			return "camera", "Reolink", ""
		}
	case strings.Contains(text, "bosch"):
		if camera {
			return "camera", "Bosch", ""
		}
	}
	return "", "", ""
}
