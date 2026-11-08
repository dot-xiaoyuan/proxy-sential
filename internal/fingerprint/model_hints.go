package fingerprint

import "strings"

// modelFamilyDeviceType maps a self-reported product family (Apple model codes,
// Android TV devices) to a clue-level device class. The model is a device
// advertisement, not a verified hardware fingerprint, so confidence stays low
// and brand/model/OS are never derived from it here.
func modelFamilyDeviceType(model string) (string, string, float64) {
	lower := strings.ToLower(strings.TrimSpace(model))
	if lower == "" {
		return "", "", 0
	}
	switch {
	case strings.HasPrefix(lower, "iphone"), strings.HasPrefix(lower, "ipod"):
		return "mobile", "Apple iPhone 系列型号", .74
	case strings.HasPrefix(lower, "ipad"):
		return "tablet", "Apple iPad 系列型号", .74
	case strings.HasPrefix(lower, "macbook"), strings.HasPrefix(lower, "imac"), strings.HasPrefix(lower, "macmini"),
		strings.HasPrefix(lower, "macpro"), strings.HasPrefix(lower, "mac studio"):
		return "desktop", "Apple Mac 系列型号", .7
	case strings.HasPrefix(lower, "appletv"), strings.HasPrefix(lower, "audioaccessory"), strings.HasPrefix(lower, "homepod"):
		return "media_device", "Apple TV/HomePod 型号", .7
	case strings.Contains(lower, "chromecast"), strings.Contains(lower, "android tv"):
		return "media_device", "Android TV/Chromecast 型号", .65
	}
	return "", "", 0
}

// modelFamilyHintFields are the protocol model fields that may carry a product
// family. A friendly hostname or a MAC OUI never feeds this hint.
var modelFamilyHintFields = []string{"mdns_model", "ssdp_model", "snmp_model", "dns_sd_model"}
