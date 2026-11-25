package devicesignal

import (
	"crypto/sha256"
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

type Observation struct {
	DestinationIP string
	IP            string
	MAC           string
	Direction     string
	Version       int
	TTL           int
}

type packetObservation struct {
	directTCP         bool
	IP, DestinationIP netip.Addr
	MAC               [6]byte
	Direction         string
	TrafficScope      string
	Version, TTL      int
	TCP               tcpFingerprint
}

type bucketKey struct {
	DiscoverySYN       bool
	IP, MAC, Direction string
	VLAN               string
	TCPStack           string
	TCPWindow          uint16
	TrafficScope       string
	Version, TTL       int
}

type tcpFingerprint struct {
	MSS         uint16
	Window      uint16
	WindowScale uint8
	Flags       uint8
	OptionCount uint8
	Options     [40]uint8
}

func (f tcpFingerprint) present() bool { return f.Flags&1 != 0 }

func (f tcpFingerprint) String() string {
	if !f.present() {
		return ""
	}
	options := make([]string, 0, f.OptionCount)
	for index := 0; index < int(f.OptionCount); index++ {
		options = append(options, fmt.Sprint(f.Options[index]))
	}
	return fmt.Sprintf("mss=%d,ws=%d,sack=%t,ts=%t,df=%t,opt=%s", f.MSS, f.WindowScale, f.Flags&2 != 0, f.Flags&4 != 0, f.Flags&8 != 0, strings.Join(options, "-"))
}

type packetBucketKey struct {
	DiscoverySYN bool
	IP           netip.Addr
	MAC          [6]byte
	Direction    string
	TrafficScope string
	Version      int
	TTL          int
	TCP          tcpFingerprint
	VLAN         string
}

func parseFrame(frame []byte) (Observation, bool) {
	value, ok := parsePacketFrame(frame)
	if !ok {
		return Observation{}, false
	}
	return Observation{IP: value.IP.String(), DestinationIP: value.DestinationIP.String(), MAC: net.HardwareAddr(value.MAC[:]).String(), Direction: value.Direction, Version: value.Version, TTL: value.TTL}, true
}

func parsePacketFrame(frame []byte) (packetObservation, bool) {
	if len(frame) < 14 {
		return packetObservation{}, false
	}
	var srcMAC [6]byte
	copy(srcMAC[:], frame[6:12])
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	offset := 14
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(frame) < offset+4 {
			return packetObservation{}, false
		}
		etherType = uint16(frame[offset+2])<<8 | uint16(frame[offset+3])
		offset += 4
	}
	switch etherType {
	case 0x0800:
		if len(frame) < offset+20 || frame[offset]>>4 != 4 {
			return packetObservation{}, false
		}
		headerLength := int(frame[offset]&0x0f) * 4
		if headerLength < 20 || len(frame) < offset+headerLength {
			return packetObservation{}, false
		}
		var source, destination [4]byte
		copy(source[:], frame[offset+12:offset+16])
		copy(destination[:], frame[offset+16:offset+20])
		value := packetObservation{IP: netip.AddrFrom4(source), MAC: srcMAC, DestinationIP: netip.AddrFrom4(destination), Direction: "unknown", Version: 4, TTL: int(frame[offset+8])}
		value.directTCP = frame[offset+9] == 6
		if value.directTCP && (uint16(frame[offset+6])<<8|uint16(frame[offset+7]))&0x1fff == 0 {
			value.TCP = parseTCPFingerprint(frame, offset+headerLength, frame[offset+6]&0x40 != 0)
		}
		value.TrafficScope = packetTTLTrafficScope(frame, value.DestinationIP, frame[offset+9], offset+headerLength, (uint16(frame[offset+6])<<8|uint16(frame[offset+7]))&0x1fff != 0)
		return value, true
	case 0x86dd:
		if len(frame) < offset+40 || frame[offset]>>4 != 6 {
			return packetObservation{}, false
		}
		var source, destination [16]byte
		copy(source[:], frame[offset+8:offset+24])
		copy(destination[:], frame[offset+24:offset+40])
		value := packetObservation{IP: netip.AddrFrom16(source), MAC: srcMAC, DestinationIP: netip.AddrFrom16(destination), Direction: "unknown", Version: 6, TTL: int(frame[offset+7])}
		value.directTCP = frame[offset+6] == 6
		if value.directTCP {
			value.TCP = parseTCPFingerprint(frame, offset+40, true)
		}
		value.TrafficScope = packetTTLTrafficScope(frame, value.DestinationIP, frame[offset+6], offset+40, false)
		return value, true
	default:
		return packetObservation{}, false
	}
}

func parseTCPFingerprint(frame []byte, offset int, df bool) tcpFingerprint {
	if offset < 0 || len(frame) < offset+20 {
		return tcpFingerprint{}
	}
	flags := frame[offset+13]
	if flags&0x17 != 0x02 {
		return tcpFingerprint{}
	}
	headerLength := int(frame[offset+12]>>4) * 4
	if headerLength < 20 || len(frame) < offset+headerLength {
		return tcpFingerprint{}
	}
	result := tcpFingerprint{Flags: 1, Window: uint16(frame[offset+14])<<8 | uint16(frame[offset+15])}
	if df {
		result.Flags |= 8
	}
	for index := offset + 20; index < offset+headerLength; {
		if int(result.OptionCount) == len(result.Options) {
			return tcpFingerprint{}
		}
		kind := frame[index]
		result.Options[result.OptionCount] = kind
		result.OptionCount++
		if kind == 0 {
			break
		}
		if kind == 1 {
			index++
			continue
		}
		if index+1 >= offset+headerLength {
			return tcpFingerprint{}
		}
		length := int(frame[index+1])
		if length < 2 || index+length > offset+headerLength {
			return tcpFingerprint{}
		}
		switch kind {
		case 2:
			if length != 4 {
				return tcpFingerprint{}
			}
			result.MSS = uint16(frame[index+2])<<8 | uint16(frame[index+3])
		case 3:
			if length != 3 {
				return tcpFingerprint{}
			}
			result.WindowScale = frame[index+2]
		case 4:
			if length != 2 {
				return tcpFingerprint{}
			}
			result.Flags |= 2
		case 8:
			if length != 10 {
				return tcpFingerprint{}
			}
			result.Flags |= 4
		}
		index += length
	}
	return result
}

func writePacketBucketWithScope(path, sensorID, interfaceName, instance string, scope *normalized.CaptureScope, bucket time.Time, values map[packetBucketKey]int) error {
	return writePacketBucketWithSource(path, sensorID, interfaceName, instance, "packet-sidecar", scope, bucket, values)
}

func writePacketBucketWithSource(path, sensorID, interfaceName, instance, source string, scope *normalized.CaptureScope, bucket time.Time, values map[packetBucketKey]int) error {
	converted := make(map[bucketKey]int, len(values))
	for key, count := range values {
		converted[bucketKey{DiscoverySYN: key.DiscoverySYN, IP: key.IP.String(), MAC: net.HardwareAddr(key.MAC[:]).String(), Direction: key.Direction, TrafficScope: key.TrafficScope, TCPStack: key.TCP.String(), TCPWindow: key.TCP.Window, VLAN: key.VLAN, Version: key.Version, TTL: key.TTL}] = count
	}
	return writeBucketWithSource(path, sensorID, interfaceName, instance, source, scope, bucket, converted)
}

func writeBucket(path, sensorID, interfaceName string, bucket time.Time, values map[bucketKey]int) error {
	return writeBucketWithScope(path, sensorID, interfaceName, "", nil, bucket, values)
}
func writeBucketWithScope(path, sensorID, interfaceName, instance string, scope *normalized.CaptureScope, bucket time.Time, values map[bucketKey]int) error {
	return writeBucketWithSource(path, sensorID, interfaceName, instance, "packet-sidecar", scope, bucket, values)
}

func writeBucketWithSource(path, sensorID, interfaceName, instance, source string, scope *normalized.CaptureScope, bucket time.Time, values map[bucketKey]int) error {
	if len(values) == 0 {
		return nil
	}
	if source == "" {
		source = "packet-sidecar"
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	keys := make([]bucketKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	encoder := json.NewEncoder(file)
	for _, key := range keys {
		identity := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00%s\x00%s", sensorID, key.IP, key.Direction, key.Version, key.TTL, key.TCPStack, bucket.UTC().Format(time.RFC3339), key.TrafficScope)
		if key.TCPWindow > 0 || key.DiscoverySYN {
			identity += fmt.Sprintf("\x00window=%d\x00vlan=%s", key.TCPWindow, key.VLAN)
		}
		if key.DiscoverySYN {
			identity += "\x00tcp_syn"
		}
		if source != "packet-sidecar" {
			identity += "\x00" + source
		}
		idSum := sha256.Sum256([]byte(identity))
		event := normalized.Event{SchemaVersion: "v1", EventID: "device-" + hex.EncodeToString(idSum[:])[:24], Source: source, SourceEventType: "ttl", Type: "device", Timestamp: bucket.UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensorID, "interface": interfaceName}, Subject: map[string]any{"ip": key.IP}, Flow: map[string]any{"src_ip": key.IP, "direction": key.Direction, "ip_version": key.Version}, Payload: map[string]any{"origin": "ttl", "neighbor_mac": key.MAC, "neighbor_role": "unverified", "ttl": key.TTL, "ip_version": key.Version, "observed_count": values[key]}, Confidence: 0.72}
		event.Observer["collector_instance_id"] = instance
		if key.TrafficScope != "" {
			event.Flow["traffic_scope"] = key.TrafficScope
		}
		if key.TCPStack != "" {
			event.Payload["tcp_stack"] = key.TCPStack
		}
		if key.TCPWindow > 0 || key.DiscoverySYN {
			event.Payload["tcp_window"] = key.TCPWindow
			if key.VLAN != "" {
				event.Payload["vlan"] = key.VLAN
			}
		}
		if key.Version == 6 {
			event.SourceEventType = "hop_limit"
			event.Payload["origin"] = "hop_limit"
			delete(event.Payload, "ttl")
			event.Payload["hop_limit"] = key.TTL
		}
		if key.DiscoverySYN {
			event.SourceEventType = "tcp_syn"
			event.Payload["origin"] = "tcp_syn"
			delete(event.Payload, "neighbor_mac")
			delete(event.Payload, "neighbor_role")
		}
		if instance != "" {
			raw, _ := json.Marshal([]string{event.EventID, instance, interfaceName, key.MAC})
			sum := sha256.Sum256(raw)
			event.EventID = "device-" + hex.EncodeToString(sum[:16])
		}
		event = scope.Apply(event)
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return file.Sync()
}
