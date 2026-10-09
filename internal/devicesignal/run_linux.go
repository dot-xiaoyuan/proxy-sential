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
			if err := writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, packetSource, opts.CaptureScope, bucket, state.packets); err != nil {
				return err
			}
			return writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, state.controls)
		case now := <-ticker.C:
			if state.droppedPacketKeys > 0 {
				log.Printf("device signal bucket reached key limit; dropped_new_keys=%d limit=%d", state.droppedPacketKeys, maxPacketBucketKeys)
			}
			if err := writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, packetSource, opts.CaptureScope, bucket, state.packets); err != nil {
				return err
			}
			if err := writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, state.controls); err != nil {
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
					if err := writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, packetSource, opts.CaptureScope, bucket, state.packets); err != nil {
						return err
					}
					return writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, state.controls)
				case now := <-ticker.C:
					if state.droppedPacketKeys > 0 {
						log.Printf("device signal bucket reached key limit; dropped_new_keys=%d limit=%d", state.droppedPacketKeys, maxPacketBucketKeys)
					}
					if err := writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, packetSource, opts.CaptureScope, bucket, state.packets); err != nil {
						return err
					}
					if err := writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, state.controls); err != nil {
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
