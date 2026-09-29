//go:build linux

package devicesignal

import (
	"context"
	"fmt"
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
}

func Run(ctx context.Context, opts Options) error {
	if opts.Interface == "" || opts.Output == "" || opts.SensorID == "" {
		return fmt.Errorf("interface, output and sensor id are required")
	}
	if opts.Bucket <= 0 {
		opts.Bucket = 5 * time.Second
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
	_ = syscall.SetNonblock(fd, true)
	values := map[packetBucketKey]int{}
	controlValues := map[string]controlSignal{}
	type recentIP struct {
		address string
		seenAt  time.Time
	}
	recentIPByMAC := map[string]recentIP{}
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
			if value, ok := parsePacketFrame(buffer[:n]); ok && value.TTL > 0 {
				if value.IP.IsPrivate() {
					recentIPByMAC[net.HardwareAddr(value.MAC[:]).String()] = recentIP{address: value.IP.String(), seenAt: time.Now().UTC()}
				}
				value.Direction = opts.CaptureScope.DirectionAddr(value.IP, value.DestinationIP)
				if value.Direction == "inbound" || value.Direction == "internal" {
					continue
				}
				if value.Direction == "unknown" && !value.IP.IsPrivate() {
					continue
				}
				values[packetBucketKey{IP: value.IP, MAC: value.MAC, Direction: value.Direction, Version: value.Version, TTL: value.TTL, TCP: value.TCP}]++
			}
			for _, signal := range parseControlFrames(buffer[:n]) {
				if signal.IP == "" {
					if recent, found := recentIPByMAC[signal.MAC]; found && time.Since(recent.seenAt) <= 24*time.Hour {
						signal.IP = recent.address
					}
				}
				controlValues[signal.key()] = signal
			}
		}
		select {
		case <-ctx.Done():
			if err := writePacketBucketWithScope(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, values); err != nil {
				return err
			}
			return writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, controlValues)
		case now := <-ticker.C:
			if err := writePacketBucketWithScope(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, values); err != nil {
				return err
			}
			if err := writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, controlValues); err != nil {
				return err
			}
			values = map[packetBucketKey]int{}
			controlValues = map[string]controlSignal{}
			bucket = now.UTC().Truncate(opts.Bucket)
		default:
			if processed == 0 {
				select {
				case <-ctx.Done():
					if err := writePacketBucketWithScope(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, values); err != nil {
						return err
					}
					return writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, controlValues)
				case now := <-ticker.C:
					if err := writePacketBucketWithScope(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, values); err != nil {
						return err
					}
					if err := writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, controlValues); err != nil {
						return err
					}
					values = map[packetBucketKey]int{}
					controlValues = map[string]controlSignal{}
					bucket = now.UTC().Truncate(opts.Bucket)
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
	}
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }
