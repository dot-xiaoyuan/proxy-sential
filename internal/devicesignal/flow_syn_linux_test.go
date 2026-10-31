//go:build linux

package devicesignal

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"proxy-sentinel/internal/normalized"
)

func TestFlowSYNCaptureRequiresExplicitValidScope(t *testing.T) {
	now := time.Now().UTC()
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site", AccessDomain: "mirror", InterfaceName: "bond0", ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
	opts := Options{Interface: "bond0", Output: "/tmp/never-written", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CaptureScope: scope, FlowSYNOnly: true}
	if err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "explicit user CIDRs") {
		t.Fatalf("missing registered user CIDRs accepted: %v", err)
	}
	scope.UserCIDRs = []string{"10.202.0.0/16"}
	opts.HandshakeOnly = true
	if err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("multiple socket filters accepted: %v", err)
	}
	opts.HandshakeOnly = false
	opts.SensorID = "other"
	if err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("foreign sensor scope accepted: %v", err)
	}
	if !flowSourceAllowed(netip.MustParseAddr("10.202.4.8"), []netip.Prefix{netip.MustParsePrefix("10.202.0.0/16")}) || flowSourceAllowed(netip.MustParseAddr("10.203.4.8"), []netip.Prefix{netip.MustParsePrefix("10.202.0.0/16")}) {
		t.Fatal("flow source range membership changed")
	}
}

func TestFlowRingTraversesOnlyBoundedFrameAndReturnsBlock(t *testing.T) {
	data := make([]byte, flowRingBlockSize*flowRingBlocks)
	ring := &flowRing{data: data}
	desc := (*unix.TpacketBlockDesc)(unsafe.Pointer(&data[0]))
	desc.Version = unix.TPACKET_V3
	header := (*unix.TpacketHdrV1)(unsafe.Pointer(&desc.Hdr[0]))
	header.Block_status = unix.TP_STATUS_USER
	header.Num_pkts = 1
	header.Offset_to_first_pkt = 48
	packet := (*unix.Tpacket3Hdr)(unsafe.Pointer(&data[48]))
	packet.Mac = 82
	frame := flowSYNFrame(false, 0x02)
	packet.Snaplen = uint32(len(frame))
	copy(data[48+82:], frame)
	count := 0
	ready, err := ring.readReady(func(frame []byte) {
		count++
		if observation, ok := parseFlowSYNFrame(frame); !ok || observation.DestinationPort != 443 {
			t.Errorf("ring changed the packet: %+v %t", observation, ok)
		}
	})
	if err != nil || !ready || count != 1 || ring.block != 1 || header.Block_status != unix.TP_STATUS_KERNEL {
		t.Fatalf("ring block was not consumed and returned: ready=%t err=%v count=%d next=%d status=%d", ready, err, count, ring.block, header.Block_status)
	}
	packet.Snaplen = 129
	header.Block_status = unix.TP_STATUS_USER
	ring.block = 0
	if _, err := ring.readReady(func([]byte) { t.Fatal("oversized frame reached parser") }); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}
