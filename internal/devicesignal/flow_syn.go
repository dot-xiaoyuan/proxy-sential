package devicesignal

import (
	"crypto/sha256"
	"encoding/binary"
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
	SourcePort      uint16
	DestinationPort uint16
	Sequence        uint32
	Acknowledgment  uint32
	Response        bool
}

type flowSYNTuple struct {
	ClientIP, ServerIP     netip.Addr
	ClientPort, ServerPort uint16
}

type flowSYNPending struct {
	sequence uint32
	seenAt   time.Time
}

// The remote IP and ephemeral client port exist only in this bounded memory
// map. A response is evidence only when its reversed tuple and acknowledgment
// match an observed initial SYN within 30 seconds.
type flowSYNMatcher struct {
	pending map[flowSYNTuple]flowSYNPending
	limit   int
	dropped int
}

func newFlowSYNMatcher(limit int) *flowSYNMatcher {
	return &flowSYNMatcher{pending: make(map[flowSYNTuple]flowSYNPending), limit: limit}
}

func (m *flowSYNMatcher) prune(now time.Time) {
	for key, item := range m.pending {
		if now.Sub(item.seenAt) > 30*time.Second {
			delete(m.pending, key)
		}
	}
}

func (m *flowSYNMatcher) recordInitial(observation flowSYNObservation, now time.Time) bool {
	if observation.Response {
		return false
	}
	key := flowSYNTuple{observation.SourceIP, observation.DestinationIP, observation.SourcePort, observation.DestinationPort}
	if item, found := m.pending[key]; found && item.sequence == observation.Sequence {
		return true
	}
	if _, found := m.pending[key]; !found && len(m.pending) >= m.limit {
		m.prune(now)
		if len(m.pending) >= m.limit {
			m.dropped++
			return false
		}
	}
	m.pending[key] = flowSYNPending{sequence: observation.Sequence, seenAt: now}
	return true
}

func (m *flowSYNMatcher) matchResponse(observation flowSYNObservation, now time.Time) (flowSYNKey, bool) {
	if !observation.Response {
		return flowSYNKey{}, false
	}
	tuple := flowSYNTuple{observation.DestinationIP, observation.SourceIP, observation.DestinationPort, observation.SourcePort}
	item, found := m.pending[tuple]
	if !found || now.Sub(item.seenAt) > 30*time.Second || observation.Acknowledgment != item.sequence+1 {
		return flowSYNKey{}, false
	}
	delete(m.pending, tuple)
	return flowSYNKey{SourceIP: tuple.ClientIP, DestinationPort: tuple.ServerPort}, true
}

// parseFlowSYNFrame accepts only direct TCP SYN and SYN-ACK headers. The kernel
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
	flags := frame[transport+13]
	if flags&0x02 == 0 || flags&0x05 != 0 || int(frame[transport+12]>>4) < 5 {
		return flowSYNObservation{}, false
	}
	response := flags&0x10 != 0
	sourcePort := binary.BigEndian.Uint16(frame[transport : transport+2])
	port := binary.BigEndian.Uint16(frame[transport+2 : transport+4])
	if sourcePort == 0 || port == 0 || source.IsUnspecified() || source.IsMulticast() || destination.IsUnspecified() || destination.IsMulticast() {
		return flowSYNObservation{}, false
	}
	return flowSYNObservation{SourceIP: source, DestinationIP: destination, SourcePort: sourcePort, DestinationPort: port,
		Sequence: binary.BigEndian.Uint32(frame[transport+4 : transport+8]), Acknowledgment: binary.BigEndian.Uint32(frame[transport+8 : transport+12]), Response: response}, true
}

func writeFlowSYNBucket(path, sensorID, interfaceName, instance string, scope *normalized.CaptureScope, bucket time.Time, values map[flowSYNKey]int, responseValues ...map[flowSYNKey]int) error {
	var responses map[flowSYNKey]int
	if len(responseValues) > 0 {
		responses = responseValues[0]
	}
	if len(values) == 0 && len(responses) == 0 {
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	keys := make([]flowSYNKey, 0, len(values)+len(responses))
	seen := make(map[flowSYNKey]bool, len(values)+len(responses))
	for key := range values {
		keys = append(keys, key)
		seen[key] = true
	}
	for key := range responses {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].SourceIP == keys[j].SourceIP {
			return keys[i].DestinationPort < keys[j].DestinationPort
		}
		return keys[i].SourceIP.Less(keys[j].SourceIP)
	})
	encoder := json.NewEncoder(file)
	for _, key := range keys {
		attempts := values[key]
		if responses[key] > 0 {
			// The matched response proves an initial SYN was seen. One durable
			// event per IP/port/bucket avoids storing the same observation twice.
			attempts = 0
		}
		for _, item := range []struct {
			count                              int
			eventType, origin, outcome, prefix string
		}{
			{attempts, "syn_attempt", "initial_syn", "unverified", "flow-syn-"},
			{responses[key], "syn_ack_observed", "matched_reverse_syn_ack", "syn_ack_observed", "flow-syn-ack-"},
		} {
			if item.count == 0 {
				continue
			}
			identity, _ := json.Marshal([]any{sensorID, instance, bucket.UTC().Format(time.RFC3339Nano), key.SourceIP.String(), key.DestinationPort, item.eventType})
			sum := sha256.Sum256(identity)
			event := normalized.Event{
				SchemaVersion: "v1", EventID: item.prefix + hex.EncodeToString(sum[:16]), Source: "flow-syn-sidecar", SourceEventType: item.eventType, Type: "flow",
				Timestamp:  bucket.UTC().Format(time.RFC3339Nano),
				Observer:   map[string]any{"sensor_id": sensorID, "interface": interfaceName, "collector_instance_id": instance},
				Subject:    map[string]any{"ip": key.SourceIP.String()},
				Flow:       map[string]any{"src_ip": key.SourceIP.String(), "proto": "tcp", "dst_port": key.DestinationPort},
				Payload:    map[string]any{"origin": item.origin, "connection_outcome": item.outcome, "observed_count": item.count},
				Confidence: 0.6,
			}
			event = scope.Apply(event)
			if err := encoder.Encode(event); err != nil {
				return err
			}
		}
	}
	return file.Sync()
}
