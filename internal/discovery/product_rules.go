package discovery

import (
	"regexp"
	"strings"
)

type productRule struct {
	pattern            *regexp.Regexp
	kind, manufacturer string
}

var campusProductRules = []productRule{
	{regexp.MustCompile(`(?i)\bDS-2CD[0-9A-Z-]+\b`), "camera", "Hikvision"},
	{regexp.MustCompile(`(?i)\bDS-(?:76|77|96)[0-9A-Z-]*NI[0-9A-Z-]*\b`), "recorder", "Hikvision"},
	{regexp.MustCompile(`(?i)\bDS-K1T[0-9A-Z-]+\b`), "access_control", "Hikvision"},
	{regexp.MustCompile(`(?i)\b(?:DH-)?IPC-H[DFW][0-9A-Z-]+\b`), "camera", "Dahua"},
	{regexp.MustCompile(`(?i)\b(?:DH-)?NVR[0-9][0-9A-Z-]+\b`), "recorder", "Dahua"},
	{regexp.MustCompile(`(?i)\bAppleTV[0-9]+,[0-9]+\b`), "media_player", "Apple"},
	{regexp.MustCompile(`(?i)\bChromecast(?: Ultra| HD| Audio)?\b`), "media_player", "Google"},
	{regexp.MustCompile(`(?i)\bZKTeco[ _-]+(?:UA[0-9]+|iClock[0-9]+)\b`), "attendance", "ZKTeco"},
}

// Only product-bearing protocol fields reach these rules. A friendly hostname,
// certificate issuer or MAC OUI cannot feed a product match.
func applyProductRules(o *Observation) {
	p := o.Evidence.Payload
	if p == nil {
		return
	}
	fields := []string{o.ModelName, str(p, "product_model"), str(p, "printer_make_and_model")}
	if o.Origin == "snmp" {
		fields = append(fields, str(p, "system_description"))
	}
	if o.Origin == "dns_sd" {
		for _, entry := range strings.FieldsFunc(protocolText(p["txt"]), func(r rune) bool { return r == ';' || r == '\n' }) {
			key, value, ok := strings.Cut(entry, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "model", "md", "product", "ty", "usb_mdl":
				fields = append(fields, value)
				if o.ModelName == "" {
					o.ModelName = cleanDescriptionText(strings.Trim(value, "()"))
				}
			}
		}
	}
	for _, value := range fields {
		for _, rule := range campusProductRules {
			if model := rule.pattern.FindString(value); model != "" {
				p["product_verified"] = true
				p["product_type"] = rule.kind
				p["product_model"] = model
				o.ModelName = model
				if o.Manufacturer == "" {
					o.Manufacturer = rule.manufacturer
				}
				return
			}
		}
	}
}
