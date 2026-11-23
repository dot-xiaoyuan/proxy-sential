package discovery

import (
	"regexp"
	"strconv"
	"strings"
)

type dhcpCandidateRule struct {
	kind   string
	vendor *regexp.Regexp
	host   *regexp.Regexp
}

var passiveDHCPRules = []dhcpCandidateRule{
	{"printer", regexp.MustCompile(`(?i)^(?:HP LaserJet|Hewlett-Packard JetDirect)(?:[ -]|$)`), regexp.MustCompile(`(?i)^(?:HP[-0-9A-F]|NPI[0-9A-F]{6})[a-z0-9-]*$`)},
	{"printer", regexp.MustCompile(`(?i)^Brother(?:[ -]|$)`), regexp.MustCompile(`(?i)^BR[NW][0-9A-F]{8,12}$`)},
	{"voip_phone", regexp.MustCompile(`(?i)^Yealink SIP-T[0-9][a-z0-9-]*(?:[ ]|$)`), regexp.MustCompile(`(?i)^(?:SIP-T[0-9][a-z0-9-]*|Yealink[-a-z0-9]*)$`)},
}

// PassiveDHCPClientCandidate requires all three fields from one observation.
// Client names and option order are clues and never confirm a hardware fact.
func PassiveDHCPClientCandidate(vendor, hostname, requestList string) string {
	parts := strings.FieldsFunc(requestList, func(r rune) bool { return r == ',' || r == ' ' })
	if len(parts) < 3 || len(parts) > 64 {
		return ""
	}
	options := make(map[int]bool, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n <= 0 || n >= 255 {
			return ""
		}
		options[n] = true
	}
	if len(options) < 3 || !options[6] {
		return ""
	}
	for _, rule := range passiveDHCPRules {
		if rule.vendor.MatchString(strings.TrimSpace(vendor)) && rule.host.MatchString(strings.TrimSpace(hostname)) {
			return rule.kind
		}
	}
	return ""
}

// Huawei's Phone and Tablet tables distinguish complete product codes, including
// codes shared by multiple retail editions. Only return an observation hint.
// https://developer.huawei.com/consumer/cn/doc/harmonyos-releases/support-device/
func dhcpReportedType(code string) string {
	switch code {
	case "ADA-AL00", "ADA-AL00U", "ADY-AL00", "ALN-AL00", "ALN-AL80", "ALT-AL10",
		"BLK-AL00", "BLK-AL80", "BRA-AL00", "CLS-AL00", "CLS-AL30", "CRS-AL00",
		"DEL-AL10", "EMA-AL00U", "HBN-AL00", "HBN-AL80", "HBP-AL00", "HED-AL00",
		"HOP-AL10", "ICL-AL10", "ICL-AL20", "KEE-AL00", "LEM-AL00", "LMR-AL00",
		"LMR-AL10", "MIA-AL00", "MIS-AL00", "MLN-AL00", "MRT-AL10", "PLA-AL10",
		"PLR-AL00", "PLR-AL30", "PLR-AL50", "SCA-AL00", "SGT-AL00", "SGT-AL10",
		"SGT-AL50", "SLY-AL00", "TLR-AL00", "VDE-AL00", "VDE-AL10", "VOL-AL00",
		"VYG-AL00", "VYG-AL30":
		return "mobile"
	case "GEM-W00", "LRT-W00", "LRT-W20", "MRDI-W00", "MRDI-W10", "PCE-W30",
		"SLG-W10", "SLG-W50", "TXZ-W10", "TXZ-W20", "WKI-W10", "XYAO-W00":
		return "tablet"
	}
	return ""
}
