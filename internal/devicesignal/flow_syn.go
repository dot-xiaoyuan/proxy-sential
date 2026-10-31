package devicesignal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"time"

	"proxy-sentinel/internal/normalized"
)

// flowSYNKey deliberately omits the destination IP and source MAC. A mirror
// can show a gateway MAC for many source IPs; the port is only an IP-scoped
// connection attempt, never a listening port or a device binding.
type flowSYNKey struct {
	SourceIP        netip.Addr
	DestinationPort uint16
}

type flowSYNObservation struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	DestinationPort uint16
}

// parseFlowSYNFrame accepts only direct TCP initial SYN headers. The kernel
// filter caps each delivered frame at 128 bytes, so application payload never
// reaches this parser. IPv6 extension headers and fragmented IPv4 traffic are
// excluded rather than guessed.
func parseFlowSYNFrame(frame []byte) (flowSYNObservation, bool) {
	if len(frame) < 14 {
		return flowSYNObservation{}, false
	}
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	offset := 14
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(frame) < offset+4 {
			return flowSYNObservation{}, false
		}
		etherType = uint16(frame[offset+2])<<8 | uint16(frame[offset+3])
		offset += 4
	}
	var source, destination netip.Addr
	transport := 0
	switch etherType {
	case 0x0800:
		if len(frame) < offset+20 || frame[offset]>>4 != 4 {
			return flowSYNObservation{}, false
		}
		headerLength := int(frame[offset]&0x0f) * 4
		if headerLength < 20 || len(frame) < offset+headerLength+20 || frame[offset+9] != 6 || (uint16(frame[offset+6])<<8|uint16(frame[offset+7]))&0x3fff != 0 {
			return flowSYNObservation{}, false
		}
		var src, dst [4]byte
		copy(src[:], frame[offset+12:offset+16])
		copy(dst[:], frame[offset+16:offset+20])
		source, destination = netip.AddrFrom4(src), netip.AddrFrom4(dst)
		transport = offset + headerLength
	case 0x86dd:
		if len(frame) < offset+40+20 || frame[offset]>>4 != 6 || frame[offset+6] != 6 {
			return flowSYNObservation{}, false
		}
		var src, dst [16]byte
		copy(src[:], frame[offset+8:offset+24])
		copy(dst[:], frame[offset+24:offset+40])
		source, destination = netip.AddrFrom16(src), netip.AddrFrom16(dst)
		transport = offset + 40
	default:
		return flowSYNObservation{}, false
	}
	if frame[transport+13]&0x12 != 0x02 || int(frame[transport+12]>>4) < 5 {
		return flowSYNObservation{}, false
	}
	port := uint16(frame[transport+2])<<8 | uint16(frame[transport+3])
	if port == 0 || source.IsUnspecified() || source.IsMulticast() || destination.IsUnspecified() || destination.IsMulticast() {
		return flowSYNObservation{}, false
	}
	return flowSYNObservation{SourceIP: source, DestinationIP: destination, DestinationPort: port}, true
}

func writeFlowSYNBucket(path, sensorID, interfaceName, instance string, scope *normalized.CaptureScope, bucket time.Time, values map[flowSYNKey]int) error {
	if len(values) == 0 {
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	keys := make([]flowSYNKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].SourceIP == keys[j].SourceIP {
			return keys[i].DestinationPort < keys[j].DestinationPort
		}
		return keys[i].SourceIP.Less(keys[j].SourceIP)
	})
	encoder := json.NewEncoder(file)
	for _, key := range keys {
		identity, _ := json.Marshal([]any{sensorID, instance, bucket.UTC().Format(time.RFC3339Nano), key.SourceIP.String(), key.DestinationPort})
		sum := sha256.Sum256(identity)
		event := normalized.Event{
			SchemaVersion: "v1", EventID: "flow-syn-" + hex.EncodeToString(sum[:16]), Source: "flow-syn-sidecar", SourceEventType: "syn_attempt", Type: "flow",
			Timestamp:  bucket.UTC().Format(time.RFC3339Nano),
			Observer:   map[string]any{"sensor_id": sensorID, "interface": interfaceName, "collector_instance_id": instance},
			Subject:    map[string]any{"ip": key.SourceIP.String()},
			Flow:       map[string]any{"src_ip": key.SourceIP.String(), "proto": "tcp", "dst_port": key.DestinationPort},
			Payload:    map[string]any{"origin": "initial_syn", "connection_outcome": "unverified", "observed_count": values[key]},
			Confidence: 0.6,
		}
		event = scope.Apply(event)
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return file.Sync()
}
