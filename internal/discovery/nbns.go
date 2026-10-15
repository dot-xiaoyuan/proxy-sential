package discovery

import "strings"

func discoveryResponseName(protocol, name string) string {
	if protocol != "nbns" {
		return strings.TrimSuffix(name, ".")
	}
	label := strings.Split(name, ".")[0]
	if len(label) != 32 {
		return ""
	}
	decoded := make([]byte, 16)
	for at := 0; at < 16; at++ {
		a, b := label[at*2], label[at*2+1]
		if a < 'A' || a > 'P' || b < 'A' || b > 'P' {
			return ""
		}
		decoded[at] = (a-'A')<<4 | (b - 'A')
	}
	return cleanDescriptionText(strings.TrimSpace(string(decoded[:15])))
}
