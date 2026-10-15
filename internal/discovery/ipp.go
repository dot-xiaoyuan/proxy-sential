package discovery

import (
	"encoding/binary"
	"fmt"
)

// ParseIPPAttributes is called only for a server response to a read-only
// Get-Printer-Attributes request. It never decodes document/job content.
func ParseIPPAttributes(raw []byte) (map[string]any, error) {
	if len(raw) < 9 || len(raw) > 1<<20 || raw[0] < 1 || raw[0] > 2 || binary.BigEndian.Uint16(raw[2:4]) > 0x0007 {
		return nil, fmt.Errorf("invalid IPP response")
	}
	p := map[string]any{"origin": "ipp", "is_response": true, "ttl": 3600}
	name := ""
	count := 0
	for at := 8; at < len(raw); {
		tag := raw[at]
		at++
		if tag == 3 {
			return p, nil
		}
		if tag <= 0x0f {
			name = ""
			continue
		}
		if at+2 > len(raw) {
			break
		}
		n := int(binary.BigEndian.Uint16(raw[at : at+2]))
		at += 2
		if at+n+2 > len(raw) {
			break
		}
		if n > 0 {
			name = string(raw[at : at+n])
		}
		at += n
		size := int(binary.BigEndian.Uint16(raw[at : at+2]))
		at += 2
		if at+size > len(raw) {
			break
		}
		count++
		if count > 1024 {
			return nil, fmt.Errorf("IPP attribute budget")
		}
		if tag >= 0x41 && tag <= 0x49 && size <= 512 {
			switch name {
			case "printer-make-and-model":
				p["printer_make_and_model"] = cleanDescriptionText(string(raw[at : at+size]))
			case "printer-name":
				p["name"] = cleanDescriptionText(string(raw[at : at+size]))
			}
		}
		at += size
	}
	return nil, fmt.Errorf("truncated IPP attributes")
}
