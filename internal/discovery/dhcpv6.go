package discovery

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

type DHCPv6Binding struct {
	IP, DUID, IAID string
	Valid          uint32
}

// Decode only server replies and explicit client releases. Relay messages are
// unwrapped with a bounded nesting depth; relay addresses are never clients.
func ParseDHCPv6(body []byte) ([]DHCPv6Binding, bool, error) {
	withdrawn := false
	for depth := 0; depth < 4; depth++ {
		if len(body) < 4 {
			return nil, false, fmt.Errorf("truncated DHCPv6")
		}
		if body[0] != 12 && body[0] != 13 {
			break
		}
		if len(body) < 34 {
			return nil, false, fmt.Errorf("truncated DHCPv6 relay")
		}
		nested := []byte(nil)
		for options := body[34:]; len(options) > 0; {
			if len(options) < 4 {
				return nil, false, fmt.Errorf("truncated DHCPv6 relay option")
			}
			code, n := binary.BigEndian.Uint16(options[:2]), int(binary.BigEndian.Uint16(options[2:4]))
			if n > len(options)-4 {
				return nil, false, fmt.Errorf("DHCPv6 option bounds")
			}
			if code == 9 {
				nested = options[4 : 4+n]
			}
			options = options[4+n:]
		}
		if nested == nil {
			return nil, false, fmt.Errorf("DHCPv6 relay message absent")
		}
		body = nested
	}
	if len(body) < 4 || (body[0] != 7 && body[0] != 8) {
		return nil, false, fmt.Errorf("DHCPv6 reply/release required")
	}
	withdrawn = body[0] == 8
	duid := ""
	bindings := []DHCPv6Binding{}
	for options := body[4:]; len(options) > 0; {
		if len(options) < 4 {
			return nil, false, fmt.Errorf("truncated DHCPv6 option")
		}
		code, n := binary.BigEndian.Uint16(options[:2]), int(binary.BigEndian.Uint16(options[2:4]))
		if n > len(options)-4 {
			return nil, false, fmt.Errorf("DHCPv6 option bounds")
		}
		value := options[4 : 4+n]
		options = options[4+n:]
		if code == 1 {
			if n > 128 {
				return nil, false, fmt.Errorf("DUID budget")
			}
			duid = hex.EncodeToString(value)
		}
		if code != 3 && code != 4 {
			continue
		}
		header := 12
		if code == 4 {
			header = 4
		}
		if len(value) < header {
			return nil, false, fmt.Errorf("truncated IA")
		}
		iaid := hex.EncodeToString(value[:4])
		for sub := value[header:]; len(sub) > 0; {
			if len(sub) < 4 {
				return nil, false, fmt.Errorf("truncated IA option")
			}
			kind, size := binary.BigEndian.Uint16(sub[:2]), int(binary.BigEndian.Uint16(sub[2:4]))
			if size > len(sub)-4 {
				return nil, false, fmt.Errorf("IA bounds")
			}
			if kind == 5 {
				if size < 24 {
					return nil, false, fmt.Errorf("truncated IAADDR")
				}
				v := sub[4 : 4+size]
				ttl := binary.BigEndian.Uint32(v[20:24])
				if withdrawn {
					ttl = 0
				}
				if ttl > 604800 {
					ttl = 604800
				}
				bindings = append(bindings, DHCPv6Binding{IP: net.IP(v[:16]).String(), IAID: iaid, Valid: ttl})
				if len(bindings) > 128 {
					return nil, false, fmt.Errorf("DHCPv6 binding budget")
				}
			}
			sub = sub[4+size:]
		}
	}
	if duid == "" {
		return nil, false, fmt.Errorf("DHCPv6 client identity absent")
	}
	for i := range bindings {
		bindings[i].DUID = duid
	}
	return bindings, withdrawn, nil
}
