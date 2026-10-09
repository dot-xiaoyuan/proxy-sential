package devicesignal

import (
	"encoding/binary"
	"net/netip"
)

// A small, bounded category preserves TTL eligibility without expanding the
// capture bucket into a per-destination/per-port flow collector.
func packetTTLTrafficScope(frame []byte, destination netip.Addr, protocol byte, transportOffset int, laterFragment bool) string {
	if destination.IsMulticast() {
		return "multicast"
	}
	broadcast := len(frame) >= 6
	for i := 0; i < 6 && broadcast; i++ {
		broadcast = frame[i] == 0xff
	}
	if broadcast || destination.String() == "255.255.255.255" {
		return "broadcast"
	}
	if !destination.IsValid() || destination.IsUnspecified() {
		return "unclassified"
	}
	if protocol == 17 {
		if laterFragment || len(frame) < transportOffset+8 {
			return "unclassified"
		}
		src := binary.BigEndian.Uint16(frame[transportOffset : transportOffset+2])
		dst := binary.BigEndian.Uint16(frame[transportOffset+2 : transportOffset+4])
		if src == 5353 || dst == 5353 {
			return "protocol_specific"
		}
	}
	if protocol == 1 || protocol == 58 {
		return "protocol_specific"
	}
	if protocol != 6 && protocol != 17 {
		return "unclassified"
	}
	return "unicast"
}
