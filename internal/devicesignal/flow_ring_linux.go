//go:build linux

package devicesignal

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The receive ring is fixed at 64 MiB. The SYN BPF still truncates each frame
// to 128 bytes, and the source map remains separately bounded.
const flowRingBlockSize = 1 << 20
const flowRingBlocks = 64
const flowRingFrameSize = 256

type flowRing struct {
	fd    int
	data  []byte
	block int
}

func newFlowRing(interfaceName string) (_ *flowRing, err error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("open flow SYN AF_PACKET socket: %w", err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(fd)
		}
	}()
	// Attach before bind and ring allocation. Otherwise the ring can collect
	// unrestricted packets during setup, including application payload.
	if err = attachSharedSignalFilter(fd); err != nil {
		return nil, fmt.Errorf("attach initial SYN filter: %w", err)
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		return nil, fmt.Errorf("bind flow SYN socket to %s: %w", interfaceName, err)
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		return nil, fmt.Errorf("select TPACKET_V3: %w", err)
	}
	request := unix.TpacketReq3{Block_size: flowRingBlockSize, Block_nr: flowRingBlocks, Frame_size: flowRingFrameSize, Frame_nr: flowRingBlockSize / flowRingFrameSize * flowRingBlocks, Retire_blk_tov: 100}
	if err = unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &request); err != nil {
		return nil, fmt.Errorf("allocate bounded flow SYN ring: %w", err)
	}
	data, err := unix.Mmap(fd, 0, flowRingBlockSize*flowRingBlocks, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map flow SYN receive ring: %w", err)
	}
	return &flowRing{fd: fd, data: data}, nil
}

func (r *flowRing) close() {
	if r == nil {
		return
	}
	_ = unix.Munmap(r.data)
	_ = unix.Close(r.fd)
}

// readReady walks one kernel-owned block without copying its packet bytes.
// The callback must finish with each slice before the block is returned.
func (r *flowRing) readReady(onFrame func([]byte)) (bool, error) {
	base := r.block * flowRingBlockSize
	block := r.data[base : base+flowRingBlockSize]
	desc := (*unix.TpacketBlockDesc)(unsafe.Pointer(&block[0]))
	header := (*unix.TpacketHdrV1)(unsafe.Pointer(&desc.Hdr[0]))
	if atomic.LoadUint32(&header.Block_status)&unix.TP_STATUS_USER == 0 {
		return false, nil
	}
	defer func() {
		atomic.StoreUint32(&header.Block_status, unix.TP_STATUS_KERNEL)
		r.block = (r.block + 1) % flowRingBlocks
	}()
	if desc.Version != unix.TPACKET_V3 || header.Num_pkts > flowRingBlockSize/flowRingFrameSize || header.Offset_to_first_pkt >= flowRingBlockSize {
		return true, fmt.Errorf("invalid flow SYN ring block header")
	}
	offset := int(header.Offset_to_first_pkt)
	for i := uint32(0); i < header.Num_pkts; i++ {
		if offset < 0 || offset+unix.SizeofTpacket3Hdr > len(block) {
			return true, fmt.Errorf("flow SYN ring packet header outside block")
		}
		packet := (*unix.Tpacket3Hdr)(unsafe.Pointer(&block[offset]))
		start := offset + int(packet.Mac)
		end := start + int(packet.Snaplen)
		if start < offset+unix.SizeofTpacket3Hdr || end < start || end > len(block) || packet.Snaplen > 128 {
			return true, fmt.Errorf("flow SYN ring packet outside bounded frame: offset=%d mac=%d snaplen=%d end=%d block=%d", offset, packet.Mac, packet.Snaplen, end, len(block))
		}
		onFrame(block[start:end])
		if i+1 < header.Num_pkts {
			if packet.Next_offset == 0 {
				return true, fmt.Errorf("flow SYN ring packet has no next offset")
			}
			offset += int(packet.Next_offset)
		}
	}
	return true, nil
}

func (r *flowRing) wait() error {
	_, err := unix.Poll([]unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}, 20)
	if err == syscall.EINTR {
		return nil
	}
	return err
}

// PACKET_STATISTICS resets both counters on read, so each call describes one
// measured bucket. V3 also reports frozen blocks for stalled readers.
func (r *flowRing) stats() (uint32, uint32, uint32, bool) {
	stats, err := unix.GetsockoptTpacketStatsV3(r.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, 0, 0, false
	}
	return stats.Packets, stats.Drops, stats.Freeze_q_cnt, true
}
