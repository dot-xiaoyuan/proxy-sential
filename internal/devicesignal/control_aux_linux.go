//go:build linux

package devicesignal

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// restoreControlVLAN restores the outer tag removed by receive offload. An
// inline tag is an inner tag, even if its VID equals the removed outer VID.
// packet(7) documents the native-endian 20-byte tpacket_auxdata layout.
// scratch is caller-owned and reused; no per-packet payload is retained here.
func restoreControlVLAN(frame, ancillary, scratch []byte) ([]byte, error) {
	msgs, err := unix.ParseSocketControlMessage(ancillary)
	if err != nil {
		return nil, err
	}
	for _, msg := range msgs {
		if msg.Header.Level != unix.SOL_PACKET || msg.Header.Type != unix.PACKET_AUXDATA {
			continue
		}
		if len(msg.Data) < 20 {
			return nil, fmt.Errorf("short packet VLAN metadata")
		}
		status := binary.NativeEndian.Uint32(msg.Data)
		if status&unix.TP_STATUS_VLAN_VALID == 0 {
			continue
		}
		tpid := uint16(0x8100)
		if status&unix.TP_STATUS_VLAN_TPID_VALID != 0 {
			tpid = binary.NativeEndian.Uint16(msg.Data[18:])
		}
		if (tpid != 0x8100 && tpid != 0x88a8) || len(frame) < 14 || len(scratch) < len(frame)+4 {
			return nil, fmt.Errorf("invalid or unbounded offloaded VLAN frame")
		}
		out := scratch[:len(frame)+4]
		copy(out[:12], frame[:12])
		binary.BigEndian.PutUint16(out[12:14], tpid)
		binary.BigEndian.PutUint16(out[14:16], binary.NativeEndian.Uint16(msg.Data[16:]))
		copy(out[16:], frame[12:])
		return out, nil
	}
	return frame, nil
}
