package discovery

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// ParseWSDiscovery deliberately rejects probes and resolves: the sender of a
// discovery question is not the device advertised in its requested Types.
func ParseWSDiscovery(body string) (map[string]any, error) {
	if len(body) == 0 || len(body) > 32768 {
		return nil, fmt.Errorf("WS-Discovery size limit")
	}
	d := xml.NewDecoder(strings.NewReader(body))
	depth := 0
	message := ""
	fields := map[string]string{}
	field := ""
	var text strings.Builder
	for {
		token, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		switch t := token.(type) {
		case xml.Directive:
			return nil, fmt.Errorf("XML directives forbidden")
		case xml.StartElement:
			depth++
			if depth > 32 {
				return nil, fmt.Errorf("XML depth limit")
			}
			switch t.Name.Local {
			case "Hello", "Bye", "ProbeMatches", "ResolveMatches":
				if message != "" && message != t.Name.Local {
					return nil, fmt.Errorf("conflicting WS-Discovery messages")
				}
				message = t.Name.Local
			case "Probe", "Resolve":
				return nil, fmt.Errorf("discovery query is not device evidence")
			}
			switch t.Name.Local {
			case "Types", "XAddrs", "Scopes", "Address", "MessageID":
				field = t.Name.Local
				text.Reset()
			}
		case xml.CharData:
			if field != "" {
				if text.Len()+len(t) > 8192 {
					return nil, fmt.Errorf("XML field limit")
				}
				text.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local == field {
				fields[field] = strings.TrimSpace(text.String())
				field = ""
			}
			depth--
		}
	}
	if message == "" || depth != 0 {
		return nil, fmt.Errorf("no WS-Discovery announcement")
	}
	p := map[string]any{"origin": "ws_discovery", "is_response": true, "message": message, "types": fields["Types"], "xaddrs": fields["XAddrs"], "scopes": fields["Scopes"], "endpoint_reference": fields["Address"], "message_id": fields["MessageID"], "ttl": 1800}
	if message == "Bye" {
		p["withdrawn"] = true
		p["ttl"] = 0
	}
	return p, nil
}
