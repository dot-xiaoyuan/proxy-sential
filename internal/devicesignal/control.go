package devicesignal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

// controlSignal is a deliberately small, credential-free representation of a
// routing or discovery protocol observation. It is converted to the standard
// event schema before it leaves the packet collector.
type controlSignal struct {
	Kind        string
	IP          string
	MAC         string
	VLAN        int
	Destination string
	Payload     map[string]any
}

func (s controlSignal) key() string {
	raw, _ := json.Marshal(s.Payload)
	return strings.Join([]string{s.Kind, s.IP, s.MAC, fmt.Sprint(s.VLAN), string(raw)}, "\x00")
}

type ethernetFrame struct {
	source, destination [6]byte
	etherType           uint16
	vlan                int
	payload             []byte
}

func parseEthernetFrame(frame []byte) (ethernetFrame, bool) {
	if len(frame) < 14 {
		return ethernetFrame{}, false
	}
	var result ethernetFrame
	copy(result.destination[:], frame[:6])
	copy(result.source[:], frame[6:12])
	result.etherType = binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	for result.etherType == 0x8100 || result.etherType == 0x88a8 {
		if len(frame) < offset+4 {
			return ethernetFrame{}, false
		}
		if result.vlan == 0 {
			result.vlan = int(binary.BigEndian.Uint16(frame[offset:offset+2]) & 0x0fff)
		}
		result.etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	result.payload = frame[offset:]
	return result, true
}

func parseControlFrame(frame []byte) (controlSignal, bool) {
	signals := parseControlFrames(frame)
	if len(signals) == 0 {
		return controlSignal{}, false
	}
	return signals[0], true
}

func parseControlFrames(frame []byte) []controlSignal {
	ethernet, ok := parseEthernetFrame(frame)
	if !ok {
		return nil
	}
	if ethernet.etherType == 0x88cc {
		if signal, found := parseLLDP(ethernet); found {
			return []controlSignal{signal}
		}
		return nil
	}
	if ethernet.etherType == 0x893a {
		return parseIEEE1905(ethernet)
	}
	if ethernet.destination == [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc} {
		if signal, found := parseCDP(ethernet); found {
			return []controlSignal{signal}
		}
	}
	if ethernet.etherType != 0x0800 || len(ethernet.payload) < 20 || ethernet.payload[0]>>4 != 4 {
		return nil
	}
	ipHeaderLength := int(ethernet.payload[0]&0x0f) * 4
	if ipHeaderLength < 20 || len(ethernet.payload) < ipHeaderLength {
		return nil
	}
	source := net.IP(ethernet.payload[12:16]).String()
	destination := net.IP(ethernet.payload[16:20]).String()
	protocol := ethernet.payload[9]
	transport := ethernet.payload[ipHeaderLength:]
	if protocol == 112 {
		if signal, found := parseVRRP(ethernet, source, destination, transport); found {
			return []controlSignal{signal}
		}
		return nil
	}
	if protocol != 17 || len(transport) < 8 {
		return nil
	}
	sourcePort, destinationPort := binary.BigEndian.Uint16(transport[:2]), binary.BigEndian.Uint16(transport[2:4])
	udpPayload := transport[8:]
	if sourcePort == 1900 || destinationPort == 1900 {
		if signal, found := parseSSDP(ethernet, source, destination, udpPayload); found {
			return []controlSignal{signal}
		}
		return nil
	}
	// IPv4 HSRP uses UDP 1985 at both ends. Matching either endpoint (or the
	// IPv6 HSRP port 2029 in this IPv4 parser) turns ordinary client traffic
	// whose ephemeral source port happens to be 1985/2029 into router evidence.
	if sourcePort == 1985 && destinationPort == 1985 {
		if signal, found := parseHSRP(ethernet, source, destination, sourcePort, destinationPort, udpPayload); found {
			return []controlSignal{signal}
		}
	}
	return nil
}

type ieee1905ClientAssociation struct {
	clientMAC      string
	bssid          string
	state          string
	associationAge int
	snapshot       bool
}

func parseIEEE1905(ethernet ethernetFrame) []controlSignal {
	// IEEE 1905.1 CMDUs use an eight-octet header followed by TLVs. Fragmented
	// messages require reassembly, so only complete, unfragmented messages are
	// emitted. Bit 7 of the flags octet marks the last fragment.
	payload := ethernet.payload
	if len(payload) < 8 || payload[0] != 0 || payload[6] != 0 || payload[7]&0x80 == 0 {
		return nil
	}
	messageType := binary.BigEndian.Uint16(payload[2:4])
	messageID := binary.BigEndian.Uint16(payload[4:6])
	sourceMAC := net.HardwareAddr(ethernet.source[:]).String()
	alMAC := sourceMAC
	interfaceMAC := ""
	vendorOUI := ""
	clients := []ieee1905ClientAssociation{}
	for tlvs := payload[8:]; len(tlvs) >= 3; {
		kind, length := tlvs[0], int(binary.BigEndian.Uint16(tlvs[1:3]))
		tlvs = tlvs[3:]
		if length > len(tlvs) {
			return nil
		}
		value := tlvs[:length]
		tlvs = tlvs[length:]
		switch kind {
		case 0:
			tlvs = nil
		case 1:
			if len(value) == 6 {
				alMAC = net.HardwareAddr(value).String()
			}
		case 2:
			if len(value) == 6 {
				interfaceMAC = net.HardwareAddr(value).String()
			}
		case 0x0b:
			if len(value) >= 3 {
				vendorOUI = fmt.Sprintf("%02x:%02x:%02x", value[0], value[1], value[2])
			}
		case 0x92:
			if len(value) != 13 {
				continue
			}
			state := "left"
			if value[12]&0x80 != 0 {
				state = "joined"
			}
			clients = append(clients, ieee1905ClientAssociation{
				clientMAC: net.HardwareAddr(value[:6]).String(), bssid: net.HardwareAddr(value[6:12]).String(), state: state,
			})
		case 0x84:
			parsed, valid := parseIEEE1905AssociatedClients(value)
			if !valid {
				return nil
			}
			clients = append(clients, parsed...)
		}
	}
	base := map[string]any{
		"origin": "ieee1905", "al_mac": alMAC, "message_type": int(messageType), "message_id": int(messageID),
	}
	if interfaceMAC != "" {
		base["interface_mac"] = interfaceMAC
	}
	if vendorOUI != "" {
		base["vendor_oui"] = vendorOUI
	}
	if ethernet.vlan > 0 {
		base["vlan"] = ethernet.vlan
	}
	signals := []controlSignal{}
	if messageType == 0x0000 {
		signals = append(signals, controlSignal{Kind: "ieee1905_topology", MAC: sourceMAC, VLAN: ethernet.vlan, Payload: base})
	}
	for _, client := range clients {
		clientPayload := make(map[string]any, len(base)+5)
		for key, value := range base {
			clientPayload[key] = value
		}
		clientPayload["client_mac"] = client.clientMAC
		clientPayload["bssid"] = client.bssid
		clientPayload["association_state"] = client.state
		if client.snapshot {
			clientPayload["topology_snapshot"] = true
			clientPayload["association_age_seconds"] = client.associationAge
		}
		signals = append(signals, controlSignal{Kind: "ieee1905_client_association", MAC: sourceMAC, VLAN: ethernet.vlan, Payload: clientPayload})
	}
	return signals
}

func parseIEEE1905AssociatedClients(value []byte) ([]ieee1905ClientAssociation, bool) {
	if len(value) < 1 {
		return nil, false
	}
	bssCount := int(value[0])
	value = value[1:]
	clients := []ieee1905ClientAssociation{}
	for bss := 0; bss < bssCount; bss++ {
		if len(value) < 8 {
			return nil, false
		}
		bssid := net.HardwareAddr(value[:6]).String()
		clientCount := int(binary.BigEndian.Uint16(value[6:8]))
		value = value[8:]
		if clientCount > len(value)/8 {
			return nil, false
		}
		for index := 0; index < clientCount; index++ {
			clients = append(clients, ieee1905ClientAssociation{
				clientMAC: net.HardwareAddr(value[:6]).String(), bssid: bssid, state: "joined",
				associationAge: int(binary.BigEndian.Uint16(value[6:8])), snapshot: true,
			})
			value = value[8:]
		}
	}
	return clients, true
}

func baseControlSignal(kind string, ethernet ethernetFrame, ip, destination string) controlSignal {
	return controlSignal{
		Kind: kind, IP: ip, Destination: destination,
		MAC: net.HardwareAddr(ethernet.source[:]).String(), VLAN: ethernet.vlan,
		Payload: map[string]any{"origin": kind},
	}
}

func parseLLDP(ethernet ethernetFrame) (controlSignal, bool) {
	signal := baseControlSignal("lldp", ethernet, "", "01:80:c2:00:00:0e")
	payload := ethernet.payload
	for len(payload) >= 2 {
		header := binary.BigEndian.Uint16(payload[:2])
		kind, length := int(header>>9), int(header&0x01ff)
		payload = payload[2:]
		if length > len(payload) {
			return controlSignal{}, false
		}
		value := payload[:length]
		payload = payload[length:]
		switch kind {
		case 0:
			payload = nil
		case 1:
			signal.Payload["chassis_id"] = lldpIdentifier(value)
		case 2:
			signal.Payload["port_id"] = lldpIdentifier(value)
		case 5:
			setPrintable(signal.Payload, "system_name", value)
		case 6:
			setPrintable(signal.Payload, "system_description", value)
		case 7:
			if len(value) >= 4 {
				signal.Payload["system_capabilities"] = capabilityNames(binary.BigEndian.Uint16(value[2:4]))
			}
		case 8:
			if address := lldpManagementAddress(value); address != "" {
				signal.Payload["management_address"] = address
				signal.IP = address
			}
		}
	}
	if len(signal.Payload) == 1 {
		return controlSignal{}, false
	}
	if signal.VLAN > 0 {
		signal.Payload["vlan"] = signal.VLAN
	}
	return signal, true
}

func lldpIdentifier(value []byte) string {
	if len(value) < 2 {
		return ""
	}
	if value[0] == 4 && len(value) == 7 {
		return net.HardwareAddr(value[1:]).String()
	}
	return strings.TrimSpace(string(value[1:]))
}

func lldpManagementAddress(value []byte) string {
	if len(value) < 3 {
		return ""
	}
	length := int(value[0])
	if length < 2 || len(value) < 1+length {
		return ""
	}
	address := value[2 : 1+length]
	switch value[1] {
	case 1:
		if len(address) == 4 {
			return net.IP(address).String()
		}
	case 2:
		if len(address) == 16 {
			return net.IP(address).String()
		}
	}
	return ""
}

func capabilityNames(bits uint16) string {
	definitions := []struct {
		bit  uint16
		name string
	}{{1, "other"}, {2, "repeater"}, {4, "bridge"}, {8, "wlan"}, {16, "router"}, {32, "telephone"}, {64, "docsis"}, {128, "station"}}
	result := make([]string, 0, 3)
	for _, definition := range definitions {
		if bits&definition.bit != 0 {
			result = append(result, definition.name)
		}
	}
	return strings.Join(result, ",")
}

func parseCDP(ethernet ethernetFrame) (controlSignal, bool) {
	payload := ethernet.payload
	if len(payload) < 12 || string(payload[:8]) != string([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}) {
		return controlSignal{}, false
	}
	signal := baseControlSignal("cdp", ethernet, "", "01:00:0c:cc:cc:cc")
	payload = payload[12:]
	for len(payload) >= 4 {
		kind, length := binary.BigEndian.Uint16(payload[:2]), int(binary.BigEndian.Uint16(payload[2:4]))
		if length < 4 || length > len(payload) {
			break
		}
		value := payload[4:length]
		payload = payload[length:]
		switch kind {
		case 1:
			setPrintable(signal.Payload, "system_name", value)
		case 3:
			setPrintable(signal.Payload, "port_id", value)
		case 4:
			if len(value) >= 4 {
				bits := binary.BigEndian.Uint32(value[:4])
				names := []string{}
				if bits&1 != 0 {
					names = append(names, "router")
				}
				if bits&8 != 0 {
					names = append(names, "switch")
				}
				if bits&16 != 0 {
					names = append(names, "host")
				}
				signal.Payload["capabilities"] = strings.Join(names, ",")
			}
		case 5:
			setPrintable(signal.Payload, "software", value)
		case 6:
			setPrintable(signal.Payload, "platform", value)
		}
	}
	if len(signal.Payload) == 1 {
		return controlSignal{}, false
	}
	if signal.VLAN > 0 {
		signal.Payload["vlan"] = signal.VLAN
	}
	return signal, true
}

func parseVRRP(ethernet ethernetFrame, source, destination string, payload []byte) (controlSignal, bool) {
	if len(payload) < 8 || payload[0]&0x0f != 1 {
		return controlSignal{}, false
	}
	signal := baseControlSignal("vrrp", ethernet, source, destination)
	signal.Payload["version"] = int(payload[0] >> 4)
	signal.Payload["virtual_router_id"] = int(payload[1])
	signal.Payload["priority"] = int(payload[2])
	signal.Payload["address_count"] = int(payload[3])
	if payload[2] == 0 {
		signal.Payload["state"] = "shutdown"
	} else {
		signal.Payload["state"] = "advertisement"
	}
	if signal.VLAN > 0 {
		signal.Payload["vlan"] = signal.VLAN
	}
	return signal, true
}

func parseHSRP(ethernet ethernetFrame, source, destination string, sourcePort, destinationPort uint16, payload []byte) (controlSignal, bool) {
	// HSRPv1 advertisements are sent to 224.0.0.2. HSRPv2 keeps UDP 1985
	// but uses 224.0.0.102 and a different TLV body, which is not decoded here.
	// Accept only the v1 fixed header instead of manufacturing fields from an
	// arbitrary UDP payload.
	if sourcePort != 1985 || destinationPort != 1985 || destination != "224.0.0.2" || len(payload) < 20 || payload[0] != 0 || payload[1] > 2 || !validHSRPState(payload[2]) {
		return controlSignal{}, false
	}
	signal := baseControlSignal("hsrp", ethernet, source, destination)
	signal.Payload["udp_port"] = 1985
	signal.Payload["version"] = int(payload[0])
	signal.Payload["opcode"] = int(payload[1])
	signal.Payload["state"] = int(payload[2])
	signal.Payload["group"] = int(payload[6])
	if signal.VLAN > 0 {
		signal.Payload["vlan"] = signal.VLAN
	}
	return signal, true
}

func validHSRPState(value byte) bool {
	switch value {
	case 0, 1, 2, 4, 8, 16:
		return true
	default:
		return false
	}
}

func parseSSDP(ethernet ethernetFrame, source, destination string, payload []byte) (controlSignal, bool) {
	text := strings.ReplaceAll(string(payload), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return controlSignal{}, false
	}
	start := strings.ToUpper(strings.TrimSpace(lines[0]))
	// M-SEARCH describes the client making a query, not the advertised device.
	if !strings.HasPrefix(start, "NOTIFY ") && !strings.HasPrefix(start, "HTTP/1.") {
		return controlSignal{}, false
	}
	signal := baseControlSignal("ssdp", ethernet, source, destination)
	for _, line := range lines[1:] {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		switch key {
		case "st", "nt", "usn", "server", "location":
			if value != "" {
				signal.Payload[key] = value
			}
		}
	}
	if len(signal.Payload) == 1 {
		return controlSignal{}, false
	}
	if signal.VLAN > 0 {
		signal.Payload["vlan"] = signal.VLAN
	}
	return signal, true
}

func setPrintable(target map[string]any, key string, value []byte) {
	text := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || r >= 32 {
			return r
		}
		return -1
	}, string(value)))
	if text != "" {
		target[key] = text
	}
}

func writeControlBucket(path, sensorID, interfaceName, instance string, scope *normalized.CaptureScope, bucket time.Time, values map[string]controlSignal) error {
	if len(values) == 0 {
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoder := json.NewEncoder(file)
	for _, key := range keys {
		signal := values[key]
		sum := sha256.Sum256([]byte(strings.Join([]string{sensorID, signal.Kind, signal.IP, signal.MAC, key, bucket.UTC().Format(time.RFC3339)}, "\x00")))
		subject := map[string]any{"entity_role": "network_device"}
		if signal.IP != "" {
			subject["ip"] = signal.IP
		}
		if signal.MAC != "" {
			subject["mac"] = signal.MAC
		}
		flow := map[string]any{"direction": "internal", "proto": signal.Kind}
		if signal.IP != "" {
			flow["src_ip"] = signal.IP
		}
		if signal.Destination != "" {
			flow["dst_ip"] = signal.Destination
		}
		event := normalized.Event{SchemaVersion: "v1", EventID: "control-" + hex.EncodeToString(sum[:16]), Source: "packet-sidecar", SourceEventType: signal.Kind, Type: "device", Timestamp: bucket.UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensorID, "interface": interfaceName}, Subject: subject, Flow: flow, Payload: signal.Payload, Confidence: 0.95}
		if instance != "" {
			event.Observer["collector_instance_id"] = instance
		}
		event = scope.Apply(event)
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return file.Sync()
}

func validSignalIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && !address.IsUnspecified()
}
