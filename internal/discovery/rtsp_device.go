package discovery

import "strings"

// RTSPDeviceIdentity maps an RTSP client User-Agent or a responder Server
// header to a camera or recorder. Playback software names are not devices.
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
	switch {
	case strings.Contains(text, "hikvision"):
		if recorder {
			return "recorder", "Hikvision", ""
		}
		return "camera", "Hikvision", ""
	case strings.Contains(text, "dahua"):
		if recorder {
			return "recorder", "Dahua", ""
		}
		return "camera", "Dahua", ""
	case strings.Contains(text, "uniview"):
		return "camera", "Uniview", ""
	case strings.Contains(text, "axis"):
		return "camera", "Axis", ""
	case strings.Contains(text, "reolink"):
		return "camera", "Reolink", ""
	case strings.Contains(text, "bosch"):
		return "camera", "Bosch", ""
	}
	return "", "", ""
}
