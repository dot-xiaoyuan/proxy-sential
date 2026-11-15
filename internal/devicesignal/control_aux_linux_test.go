//go:build linux

package devicesignal

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func controlAux(status uint32, tci, tpid uint16) []byte {
	b := make([]byte, unix.CmsgSpace(20))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.SOL_PACKET, unix.PACKET_AUXDATA
	h.SetLen(unix.CmsgLen(20))
	d := b[unix.CmsgLen(0):]
	binary.NativeEndian.PutUint32(d, status)
	binary.NativeEndian.PutUint16(d[16:], tci)
	binary.NativeEndian.PutUint16(d[18:], tpid)
	return b
}

func TestControlVLANOffloadRestoration(t *testing.T) {
	for _, tags := range [][]uint16{{4005}, {3191, 38}, {38, 38}, {0}} {
		frame := taggedARP(tags[1:]...)
		got, err := restoreControlVLAN(frame, controlAux(unix.TP_STATUS_VLAN_VALID|unix.TP_STATUS_VLAN_TPID_VALID, tags[0], 0x8100), make([]byte, len(frame)+4))
		if err != nil || !bytes.Equal(got, taggedARP(tags...)) {
			t.Fatalf("offload did not restore exact frame %v: %x %v", tags, got, err)
		}
	}
	plain := taggedARP()
	got, err := restoreControlVLAN(plain, controlAux(0, 4005, 0x8100), nil)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("invalid VLAN metadata became an identity")
	}
	for _, aux := range [][]byte{controlAux(unix.TP_STATUS_VLAN_VALID|unix.TP_STATUS_VLAN_TPID_VALID, 1, 0x0800), controlAux(unix.TP_STATUS_VLAN_VALID, 1, 0)[:unix.CmsgLen(0)+2]} {
		if _, err := restoreControlVLAN(plain, aux, make([]byte, len(plain)+4)); err == nil {
			t.Fatal("malformed auxiliary data accepted")
		}
	}
}
