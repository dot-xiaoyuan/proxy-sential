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
	ethernet, ok := parseEthernetFrame(frame)
	if !ok {
		return controlSignal{}, false
	}
	if ethernet.etherType == 0x88cc {
		return parseLLDP(ethernet)
	}
	if ethernet.destination == [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc} {
		if signal, found := parseCDP(ethernet); found {
			return signal, true
		}
	}
	if ethernet.etherType != 0x0800 || len(ethernet.payload) < 20 || ethernet.payload[0]>>4 != 4 {
		return controlSignal{}, false
	}
	ipHeaderLength := int(ethernet.payload[0]&0x0f) * 4
	if ipHeaderLength < 20 || len(ethernet.payload) < ipHeaderLength {
		return controlSignal{}, false
	}
	source := net.IP(ethernet.payload[12:16]).String()
	destination := net.IP(ethernet.payload[16:20]).String()
	protocol := ethernet.payload[9]
	transport := ethernet.payload[ipHeaderLength:]
	if protocol == 112 {
		return parseVRRP(ethernet, source, destination, transport)
	}
	if protocol != 17 || len(transport) < 8 {
		return controlSignal{}, false
	}
	sourcePort, destinationPort := binary.BigEndian.Uint16(transport[:2]), binary.BigEndian.Uint16(transport[2:4])
	udpPayload := transport[8:]
	if sourcePort == 1900 || destinationPort == 1900 {
		return parseSSDP(ethernet, source, destination, udpPayload)
	}
	if sourcePort == 1985 || destinationPort == 1985 || sourcePort == 2029 || destinationPort == 2029 {
		return parseHSRP(ethernet, source, destination, sourcePort, destinationPort, udpPayload)
	}
	return controlSignal{}, false
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
	if len(payload) < 8 {
		return controlSignal{}, false
	}
	signal := baseControlSignal("hsrp", ethernet, source, destination)
	signal.Payload["udp_port"] = int(firstNonZeroPort(destinationPort, sourcePort))
	if sourcePort == 1985 || destinationPort == 1985 {
		signal.Payload["version"] = int(payload[5])
		signal.Payload["opcode"] = int(payload[0])
		signal.Payload["state"] = int(payload[1])
		signal.Payload["group"] = int(payload[6])
	} else {
		signal.Payload["version"] = 2
	}
	if signal.VLAN > 0 {
		signal.Payload["vlan"] = signal.VLAN
	}
	return signal, true
}

func firstNonZeroPort(values ...uint16) uint16 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
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
