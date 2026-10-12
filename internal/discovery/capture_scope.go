package discovery

import (
	"fmt"
	"net/netip"
	"proxy-sentinel/internal/normalized"
	"strings"
)

// ParseCaptureCIDRs accepts an explicit capture scope for the independent
// discovery worker. An empty scope must never turn into all-network capture.
func ParseCaptureCIDRs(raw string) ([]netip.Prefix, error) {
	values := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	if len(values) == 0 {
		return nil, fmt.Errorf("passive discovery allowed CIDRs are required")
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 {
			return nil, fmt.Errorf("invalid passive discovery CIDR %q", value)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func filterCaptureEvents(events []normalized.Event, allow []netip.Prefix) []normalized.Event {
	kept := events[:0]
	for _, event := range events {
		ip, err := netip.ParseAddr(str(event.Subject, "ip"))
		if err != nil {
			continue
		}
		for _, prefix := range allow {
			if prefix.Contains(ip.Unmap()) {
				kept = append(kept, event)
				break
			}
		}
	}
	return kept
}
