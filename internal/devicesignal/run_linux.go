//go:build linux

package devicesignal

import (
	"context"
	"fmt"
	"log"
	"net"
	"proxy-sentinel/internal/normalized"
	"syscall"
	"time"
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
	if opts.RouterProtocolsOnly {
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
	// Shutdown writes the state the tracker still holds.
	flushControls := func(at time.Time, controls map[string]controlSignal) error {
		return writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, at, selectControls(controlTracker, at, controls))
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
			state.droppedPacketKeys = 0
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
					state.droppedPacketKeys = 0
					bucket = now.UTC().Truncate(opts.Bucket)
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
	}
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }
