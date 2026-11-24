//go:build linux

package devicesignal

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestOffloadedHandshakeRetainsBothVLANTags(t *testing.T) {
	frame := make([]byte, 84)
	copy(frame[:12], []byte{2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10})
	binary.BigEndian.PutUint16(frame[12:14], 0x8100)
	binary.BigEndian.PutUint16(frame[14:16], 4)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	buf := append(make([]byte, 4), frame...)
	cmsg := make([]byte, syscall.CmsgSpace(20))
	header := (*syscall.Cmsghdr)(unsafe.Pointer(&cmsg[0]))
	header.Level = unix.SOL_PACKET
	header.Type = unix.PACKET_AUXDATA
	header.SetLen(syscall.CmsgLen(20))
	data := cmsg[syscall.CmsgLen(0):]
	binary.NativeEndian.PutUint32(data, unix.TP_STATUS_VLAN_VALID|unix.TP_STATUS_VLAN_TPID_VALID)
	binary.NativeEndian.PutUint16(data[16:18], 2809)
	binary.NativeEndian.PutUint16(data[18:20], 0x88a8)
	restored, err := restoreHandshakeVLAN(buf, len(frame), cmsg)
	eth, ok := parseEthernetFrame(restored)
	if err != nil || !ok || eth.outerVLAN != 2809 || eth.innerVLAN != 4 || !bytes.Equal(restored[:12], frame[:12]) || !bytes.Equal(restored[16:], frame[12:]) {
		t.Fatalf("wrong VLAN reconstruction: outer=%d inner=%d err=%v", eth.outerVLAN, eth.innerVLAN, err)
	}
}
