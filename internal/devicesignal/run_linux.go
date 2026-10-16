//go:build linux

package devicesignal

import (
	"context"
	"fmt"
	"log"
	"net"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
	"syscall"
	"time"
	"unsafe"
)

type Options struct {
	CollectorInstanceID string
	CaptureScope        *normalized.CaptureScope
	Interface           string
	Output              string
	SensorID            string
	Bucket              time.Duration
	// StateLiveness bounds how often an unchanged device state is rewritten. Zero keeps the
	// historical behaviour of writing every key every bucket.
	StateLiveness       time.Duration
	RouterProtocolsOnly bool
	SharedSignalsOnly   bool
	// HandshakeOnly attaches the bounded TLS ClientHello / HTTP request BPF and writes device
	// summaries of handshake fields. It runs as its own process so the router control filter
	// and its output stay unchanged.
	HandshakeOnly bool
}

func Run(ctx context.Context, opts Options) error {
	if opts.Interface == "" || opts.Output == "" || opts.SensorID == "" {
		return fmt.Errorf("interface, output and sensor id are required")
	}
	if opts.Bucket <= 0 {
		opts.Bucket = 5 * time.Second
	}
	if opts.RouterProtocolsOnly && opts.SharedSignalsOnly {
		return fmt.Errorf("router protocol and shared signal filters are mutually exclusive")
	}
	if opts.HandshakeOnly && (opts.RouterProtocolsOnly || opts.SharedSignalsOnly) {
		return fmt.Errorf("handshake filter cannot be combined with router or shared filters: one socket takes one filter")
	}
	iface, err := net.InterfaceByName(opts.Interface)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(0x0003), Ifindex: iface.Index}); err != nil {
		return fmt.Errorf("bind %s: %w", opts.Interface, err)
	}
	if opts.HandshakeOnly {
		if err := attachHandshakeFilter(fd); err != nil {
			return fmt.Errorf("attach handshake BPF: %w", err)
		}
	} else if opts.RouterProtocolsOnly {
		if err := attachRouterProtocolFilter(fd); err != nil {
			return fmt.Errorf("attach router protocol BPF: %w", err)
		}
	} else if opts.SharedSignalsOnly {
		if err := attachSharedSignalFilter(fd); err != nil {
			return fmt.Errorf("attach shared signal BPF: %w", err)
		}
	}
	_ = syscall.SetNonblock(fd, true)
	state := newCaptureBucket()
	state.handshakeEnabled = opts.HandshakeOnly
	packetSource := "packet-sidecar"
	if opts.SharedSignalsOnly {
		packetSource = "shared-syn-sidecar"
	}
	tracker := newStateChangeTracker[packetBucketKey](opts.StateLiveness)
	controlTracker := newStateChangeTracker[string](opts.StateLiveness)
	// A device state that has not changed carries no information: write new keys at once,
	// rewrite a still-present key once per liveness interval, and fold the rest into it.
	flushPackets := func(at time.Time, packets map[packetBucketKey]int) error {
		return writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, packetSource, opts.CaptureScope, at, tracker.filter(at, packets))
	}
	coverageFrom := time.Now().UTC()
	// Shutdown writes the state the tracker still holds.
	flushControls := func(at time.Time, controls map[string]controlSignal) error {
		if opts.HandshakeOnly {
			end := time.Now().UTC()
			stats, known := packetDropStats(fd)
			coverage := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: coverageFrom, To: end, KernelStatsKnown: known, Dropped: uint64(stats), KeyDrops: state.droppedPacketKeys, ParseUnknown: state.handshakeParseFailures, Stopped: ctx.Err() != nil}
			for _, summary := range state.handshakes {
				summary.coverage = coverage
				coverage.Truncated += summary.truncated
				coverage.Overflow += summary.overflow
			}
			// Per-IP summaries inherit only unlocatable loss, never another IP’s truncation.
			for _, summary := range state.handshakes {
				summary.coverage.Truncated = 0
				summary.coverage.Overflow = 0
			}
			coverage.Omitted = max(0, len(state.handshakes)-handshakeBucketLimit())
			if err := writeHandshakeBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, at, state.handshakes); err != nil {
				return err
			}
			if err := writeHandshakeCoverage(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, coverage); err != nil {
				return err
			}
			coverageFrom = end
		}
		selected := selectControls(controlTracker, at, controls)
		if !opts.HandshakeOnly && !opts.SharedSignalsOnly {
			end := time.Now().UTC()
			stats, known := packetDropStats(fd)
			coverage := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: coverageFrom, To: end, KernelStatsKnown: known, Dropped: uint64(stats), ParseUnknown: state.controlParseFailures, KeyDrops: state.controlKeyDrops, Stopped: ctx.Err() != nil}
			for key, signal := range selected {
				if signal.Kind == "ieee1905_client_snapshot" || signal.Kind == "ieee1905_client_association" {
					// Copy: the liveness tracker must compare only protocol content.
					payload := make(map[string]any, len(signal.Payload)+1)
					for k, v := range signal.Payload {
						payload[k] = v
					}
					payload["capture_coverage"] = coverage
					signal.Payload = payload
					selected[key] = signal
				}
			}
			if err := writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, at, selected); err != nil {
				return err
			}
			if err := writeCaptureCoverage(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, "packet-sidecar", opts.CaptureScope, coverage); err != nil {
				return err
			}
			coverageFrom = end
			return nil
		}
		return writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, at, selected)
	}
	// Shutdown writes the state the tracker still holds.
	flushHeld := func(at time.Time) error {
		held := tracker.pending()
		if len(held) == 0 {
			return nil
		}
		return writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, packetSource, opts.CaptureScope, at, held)
	}
	bucket := time.Now().UTC().Truncate(opts.Bucket)
	ticker := time.NewTicker(opts.Bucket)
	defer ticker.Stop()
	buffer := make([]byte, 65536)
	for {
		processed := 0
		// A saturated mirror interface may always have another frame ready.
		// Bound each receive burst so the bucket ticker cannot be starved and
		// observations do not grow in memory indefinitely.
		for processed < 4096 {
			n, _, recvErr := syscall.Recvfrom(fd, buffer, 0)
			if recvErr == syscall.EAGAIN || recvErr == syscall.EWOULDBLOCK {
				break
			}
			if recvErr != nil {
				return recvErr
			}
			processed++
			state.addFrame(buffer[:n], opts.CaptureScope)
		}
		select {
		case <-ctx.Done():
			if state.droppedPacketKeys > 0 {
				log.Printf("device signal bucket reached key limit; dropped_new_keys=%d limit=%d", state.droppedPacketKeys, maxPacketBucketKeys)
			}
			if err := flushPackets(bucket, state.packets); err != nil {
				return err
			}
			if err := flushHeld(bucket); err != nil {
				return err
			}
			return flushControls(bucket, state.controls)
		case now := <-ticker.C:
			if state.droppedPacketKeys > 0 {
				log.Printf("device signal bucket reached key limit; dropped_new_keys=%d limit=%d", state.droppedPacketKeys, maxPacketBucketKeys)
			}
			if err := flushPackets(bucket, state.packets); err != nil {
				return err
			}
			if err := flushControls(bucket, state.controls); err != nil {
				return err
			}
			state.packets = map[packetBucketKey]int{}
			state.controls = map[string]controlSignal{}
			state.handshakes = map[handshakeKey]*handshakeSummary{}
			state.droppedPacketKeys = 0
			state.handshakeParseFailures = 0
			state.handshakeFeatureSamples = 0
			state.controlParseFailures = 0
			state.controlKeyDrops = 0
			bucket = now.UTC().Truncate(opts.Bucket)
		default:
			if processed == 0 {
				select {
				case <-ctx.Done():
					if state.droppedPacketKeys > 0 {
						log.Printf("device signal bucket reached key limit; dropped_new_keys=%d limit=%d", state.droppedPacketKeys, maxPacketBucketKeys)
					}
					if err := flushPackets(bucket, state.packets); err != nil {
						return err
					}
					if err := flushHeld(bucket); err != nil {
						return err
					}
					return flushControls(bucket, state.controls)
				case now := <-ticker.C:
					if state.droppedPacketKeys > 0 {
						log.Printf("device signal bucket reached key limit; dropped_new_keys=%d limit=%d", state.droppedPacketKeys, maxPacketBucketKeys)
					}
					if err := flushPackets(bucket, state.packets); err != nil {
						return err
					}
					if err := flushControls(bucket, state.controls); err != nil {
						return err
					}
					state.packets = map[packetBucketKey]int{}
					state.controls = map[string]controlSignal{}
					state.handshakes = map[handshakeKey]*handshakeSummary{}
					state.droppedPacketKeys = 0
					state.handshakeParseFailures = 0
					state.handshakeFeatureSamples = 0
					state.controlParseFailures = 0
					state.controlKeyDrops = 0
					bucket = now.UTC().Truncate(opts.Bucket)
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
	}
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }

// PACKET_STATISTICS resets the socket counters on every successful read.
func packetDropStats(fd int) (uint32, bool) {
	var stats struct{ Packets, Drops uint32 }
	length := uint32(unsafe.Sizeof(stats))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_PACKET, syscall.PACKET_STATISTICS, uintptr(unsafe.Pointer(&stats)), uintptr(unsafe.Pointer(&length)), 0)
	return stats.Drops, errno == 0 && length >= 8
}
