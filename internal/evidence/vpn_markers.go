package evidence

import "strings"

func vpnRuleSignatureText(signature string) string {
	text := strings.ToLower(strings.TrimSpace(signature))
	for _, namespace := range []string{"proxy_sentinel", "proxy-sentinel"} {
		if strings.HasPrefix(text, namespace) && (len(text) == len(namespace) || !markerWordByte(text[len(namespace)])) {
			return strings.TrimLeft(text[len(namespace):], " :_-\t")
		}
	}
	return text
}

// HasVPNDomainHint shares the institutional VPN exclusion with review views.
func HasVPNDomainHint(value string) bool {
	return HasVPNHint(value) && !isInstitutionalVPNDomain(value)
}

func markerWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func containsVPNMarker(text, marker string) bool {
	for offset := 0; offset < len(text); {
		found := strings.Index(text[offset:], marker)
		if found < 0 {
			return false
		}
		start := offset + found
		end := start + len(marker)
		// Numbered VPN/proxy DNS labels are explicit markers; word continuations
		// such as vpn2client remain outside this classifier.
		if marker == "vpn" || marker == "proxy" {
			for end < len(text) && text[end] >= '0' && text[end] <= '9' {
				end++
			}
		}
		if (start == 0 || !markerWordByte(text[start-1])) && (end == len(text) || !markerWordByte(text[end])) {
			return true
		}
		offset = start + len(marker)
	}
	return false
}

func vpnConfidenceKey(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "proxy_sentinel_confidence" || value == "proxy-sentinel-confidence"
}

func declaredVPNRuleConfidence(metadata any) string {
	result := ""
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if rank[value] > 0 && (result == "" || rank[value] < rank[result]) {
			result = value
		}
	}
	var addValue func(any)
	addValue = func(value any) {
		switch value := value.(type) {
		case string:
			add(value)
		case []string:
			for _, item := range value {
				add(item)
			}
		case []any:
			for _, item := range value {
				addValue(item)
			}
		}
	}
	parseDeclaration := func(value string) {
		for _, declaration := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' }) {
			fields := strings.Fields(strings.ReplaceAll(declaration, "=", " "))
			if len(fields) == 2 && vpnConfidenceKey(fields[0]) {
				add(fields[1])
			}
		}
	}
	switch value := metadata.(type) {
	case map[string]any:
		for key, item := range value {
			if vpnConfidenceKey(key) {
				addValue(item)
			}
		}
	case map[string]string:
		for key, item := range value {
			if vpnConfidenceKey(key) {
				add(item)
			}
		}
	case []string:
		for _, item := range value {
			parseDeclaration(item)
		}
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok {
				parseDeclaration(text)
			}
		}
	case string:
		parseDeclaration(value)
	}
	return result
}
