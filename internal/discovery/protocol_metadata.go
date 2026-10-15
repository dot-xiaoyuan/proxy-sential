package discovery

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"net"
	"strings"
)

func ParseSNMPResponse(body []byte) (map[string]any, error) {
	if len(body) == 0 || len(body) > 65535 {
		return nil, fmt.Errorf("SNMP size limit")
	}
	parser := &gosnmp.GoSNMP{}
	packet, err := parser.SnmpDecodePacket(body)
	if err != nil {
		return nil, fmt.Errorf("invalid or encrypted SNMP")
	}
	if packet.PDUType != gosnmp.GetResponse || packet.Error != gosnmp.NoError {
		return nil, fmt.Errorf("SNMP response required")
	}
	return snmpProductPayload(packet), nil
}
func snmpProductPayload(packet *gosnmp.SnmpPacket) map[string]any {
	p := map[string]any{"origin": "snmp", "is_response": true, "ttl": 3600}
	for _, v := range packet.Variables {
		oid := strings.TrimPrefix(v.Name, ".")
		value := fmt.Sprint(v.Value)
		if b, ok := v.Value.([]byte); ok {
			value = string(b)
		}
		if len(value) > 512 {
			value = value[:512]
		}
		switch {
		case oid == "1.3.6.1.2.1.1.1.0":
			p["system_description"] = value
		case oid == "1.3.6.1.2.1.1.2.0":
			p["system_object_id"] = strings.TrimPrefix(value, ".")
		case oid == "1.3.6.1.2.1.1.5.0":
			p["name"] = value
		case strings.HasPrefix(oid, "1.3.6.1.2.1.25.3.2.1.2."):
			p["hr_device_type"] = strings.TrimPrefix(value, ".")
		case strings.HasPrefix(oid, "1.3.6.1.2.1.47.1.1.1.1.13."):
			p["product_model"] = value
		case strings.HasPrefix(oid, "1.3.6.1.2.1.47.1.1.1.1.12."):
			p["manufacturer"] = value
		}
	}
	// Community strings, authentication values and unrestricted variable values
	// never leave the parser.
	return p
}

func ParseBACnetAnnouncement(body []byte) (map[string]any, error) {
	if len(body) < 12 || len(body) > 4096 || body[0] != 0x81 || int(binary.BigEndian.Uint16(body[2:4])) != len(body) {
		return nil, fmt.Errorf("invalid BACnet BVLC")
	}
	offset := 4
	announcer := ""
	switch body[1] {
	case 0x04:
		if len(body) < 10 {
			return nil, fmt.Errorf("truncated forwarded BACnet announcement")
		}
		announcer = net.IP(body[4:8]).String()
		offset += 6
	case 0x0a, 0x0b:
	default:
		return nil, fmt.Errorf("unsupported BACnet BVLC")
	}
	if len(body) < offset+2 || body[offset] != 1 {
		return nil, fmt.Errorf("invalid BACnet NPDU")
	}
	control := body[offset+1]
	offset += 2
	if control&0x80 != 0 {
		return nil, fmt.Errorf("BACnet network message")
	}
	if control&0x20 != 0 {
		if len(body) < offset+3 {
			return nil, fmt.Errorf("truncated BACnet destination")
		}
		n := int(body[offset+2])
		offset += 3 + n
	}
	if control&0x08 != 0 {
		if len(body) < offset+3 {
			return nil, fmt.Errorf("truncated BACnet source")
		}
		n := int(body[offset+2])
		offset += 3 + n
	}
	if control&0x20 != 0 {
		offset++
	}
	if len(body) < offset+7 || body[offset] != 0x10 || body[offset+1] != 0 || body[offset+2] != 0xc4 {
		return nil, fmt.Errorf("BACnet I-Am required")
	}
	object := binary.BigEndian.Uint32(body[offset+3 : offset+7])
	if object>>22 != 8 {
		return nil, fmt.Errorf("BACnet device object required")
	}
	return map[string]any{"origin": "bacnet", "is_response": true, "ttl": 3600, "announcer_ip": announcer, "service_instance": fmt.Sprint(object & 0x3fffff), "device_identifier": fmt.Sprint(object & 0x3fffff), "object_type": "device"}, nil
}

func ParseCoAPResponse(body []byte) (map[string]any, error) {
	if len(body) < 4 || len(body) > 16384 || body[0]>>6 != 1 || body[1]>>5 != 2 {
		return nil, fmt.Errorf("CoAP success response required")
	}
	token := int(body[0] & 15)
	if token > 8 || len(body) < 4+token {
		return nil, fmt.Errorf("invalid CoAP token")
	}
	offset := 4 + token
	number := 0
	format := -1
	extended := func(n byte) (int, error) {
		switch n {
		case 13:
			if offset >= len(body) {
				return 0, fmt.Errorf("CoAP option truncated")
			}
			v := int(body[offset]) + 13
			offset++
			return v, nil
		case 14:
			if offset+2 > len(body) {
				return 0, fmt.Errorf("CoAP option truncated")
			}
			v := int(binary.BigEndian.Uint16(body[offset:offset+2])) + 269
			offset += 2
			return v, nil
		case 15:
			return 0, fmt.Errorf("reserved CoAP option")
		}
		return int(n), nil
	}
	for offset < len(body) && body[offset] != 0xff {
		header := body[offset]
		offset++
		delta, e := extended(header >> 4)
		if e != nil {
			return nil, e
		}
		n, e := extended(header & 15)
		if e != nil || offset+n > len(body) {
			return nil, fmt.Errorf("CoAP option bounds")
		}
		number += delta
		if number == 12 {
			format = 0
			for _, v := range body[offset : offset+n] {
				format = format*256 + int(v)
			}
		}
		offset += n
	}
	p := map[string]any{"origin": "coap", "is_response": true, "ttl": 1800, "content_format": format}
	if format == 40 && offset < len(body) {
		text := string(body[offset+1:])
		if len(text) > 8192 {
			return nil, fmt.Errorf("CoAP resource budget")
		}
		p["resource_description"] = text
		for _, kind := range []string{"oic.d.sensor", "oic.d.tv", "oic.d.camera", "oic.d.gateway"} {
			if strings.Contains(text, `rt="`+kind+`"`) {
				p["device_resource_type"] = kind
			}
		}
	}
	if format == 50 && offset < len(body) {
		var doc struct {
			RT   []string `json:"rt"`
			DI   string   `json:"di"`
			Name string   `json:"n"`
		}
		if json.Unmarshal(body[offset+1:], &doc) == nil && doc.DI != "" {
			p["service_instance"] = doc.DI
			p["name"] = cleanDescriptionText(doc.Name)
			for _, kind := range doc.RT {
				switch kind {
				case "oic.d.sensor", "oic.d.tv", "oic.d.camera", "oic.d.gateway":
					p["device_resource_type"] = kind
				}
			}
		}
	}
	return p, nil
}
