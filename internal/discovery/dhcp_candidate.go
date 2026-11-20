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
