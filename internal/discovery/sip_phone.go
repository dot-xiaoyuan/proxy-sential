package discovery

import "strings"

// SIPPhoneIdentity maps a self-reported SIP User-Agent to a phone model.
// Only well-known phone stacks are mapped; PBX, gateway and generic SIP stacks
// return empty so a server-side agent never becomes an endpoint phone.
func SIPPhoneIdentity(userAgent string) (deviceType, brand, model string) {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return "", "", ""
	}
	fields := strings.Fields(ua)
	switch {
	case strings.HasPrefix(ua, "Huawei eSpace ") && len(fields) >= 3:
		return "voip_phone", "Huawei", "eSpace " + fields[2]
	case strings.HasPrefix(ua, "Yealink ") && len(fields) >= 2:
		return "voip_phone", "Yealink", fields[1]
	case strings.HasPrefix(ua, "Cisco-CP-") && len(fields) >= 1:
		model := strings.SplitN(strings.TrimPrefix(fields[0], "Cisco-CP-"), "/", 2)[0]
		if model != "" {
			return "voip_phone", "Cisco", "CP-" + model
		}
	case strings.HasPrefix(ua, "Grandstream ") && len(fields) >= 2:
		return "voip_phone", "Grandstream", fields[1]
	case strings.HasPrefix(ua, "snom") && len(fields) >= 1:
		return "voip_phone", "Snom", fields[0]
	case strings.HasPrefix(ua, "Fanvil ") && len(fields) >= 2:
		return "voip_phone", "Fanvil", fields[1]
	case strings.HasPrefix(ua, "Avaya ") && len(fields) >= 2:
		return "voip_phone", "Avaya", fields[1]
	case strings.HasPrefix(ua, "Mitel ") && len(fields) >= 2:
		return "voip_phone", "Mitel", fields[1]
	case strings.HasPrefix(ua, "Panasonic ") && len(fields) >= 2:
		return "voip_phone", "Panasonic", fields[1]
	case strings.HasPrefix(ua, "OpenStage ") && len(fields) >= 2:
		return "voip_phone", "Unify", "OpenStage " + fields[1]
	case strings.HasPrefix(ua, "Polycom"):
		return "voip_phone", "Polycom", polycomModel(ua)
	}
	return "", "", ""
}

func polycomModel(ua string) string {
	// PolycomSoundPointIP-SPIP_550-UA/3.2.2.1138, Polycom VVX 411, Trio 8800.
	rest := strings.TrimSpace(strings.TrimPrefix(ua, "Polycom"))
	rest = strings.TrimPrefix(rest, "SoundPointIP-")
	if rest == "" {
		return ""
	}
	if fields := strings.Fields(rest); len(fields) > 0 {
		return strings.SplitN(fields[0], "-UA", 2)[0]
	}
	return ""
}
