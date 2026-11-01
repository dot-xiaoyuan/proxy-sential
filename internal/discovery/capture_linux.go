//go:build linux

package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
	"syscall"
	"time"
)

// Capture spools standard events on a separate goroutine; packet reads never wait on database work.
func Capture(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix) error {
	return CaptureConfigured(ctx, iface, spool, source, allow, DefaultCollectionConfig())
}
func CaptureConfigured(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix, config CollectionConfig) (result error) {
	return captureConfiguredWithPersist(ctx, iface, spool, source, allow, config, 2000, 8<<20, 100*time.Millisecond, func(b []byte) error {
		h := sha256.Sum256(b)
		path := filepath.Join(spool, hex.EncodeToString(h[:16])+".json")
		if e := writeDurableSpool(path+".tmp", b); e != nil {
			return e
		}
		if e := os.Rename(path+".tmp", path); e != nil {
			return e
		}
		dir, e := os.Open(spool)
		if e != nil {
			return e
		}
		defer dir.Close()
		return dir.Sync()
	})
}

func CaptureStreamConfigured(ctx context.Context, iface, statsDir string, source Source, allow []netip.Prefix, config CollectionConfig, journal PassiveStreamJournal, scope *normalized.CaptureScope, onSegment func(CapturedSegment) error) error {
	if journal == nil || scope == nil {
		return fmt.Errorf("passive stream capture needs durable journal and scope")
	}
	return captureConfiguredWithPersist(ctx, iface, statsDir, source, allow, config, streamlog.MaxSegmentEvents, 1<<20, passiveCaptureCoalesceWindow, func(b []byte) error {
		var events []normalized.Event
		if err := json.Unmarshal(b, &events); err != nil {
			return err
		}
		captured, err := appendPassiveStreamBatch(ctx, journal, source, scope, events)
		if err != nil {
			return err
		}
		if onSegment != nil {
			return onSegment(captured)
		}
		return nil
	})
}

func captureConfiguredWithPersist(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix, config CollectionConfig, maxEvents, maxBytes int, coalesceWindow time.Duration, persist func([]byte) error) (result error) {
	if len(allow) == 0 {
		return fmt.Errorf("passive capture requires allowed CIDRs")
	}
	i, e := net.InterfaceByName(iface)
	if e != nil {
		return e
	}
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(3)))
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = attachDiscoveryFilter(fd, config); e != nil {
		return e
	}
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(3), Ifindex: i.Index}); e != nil {
		return e
	}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000})
	if e = os.MkdirAll(spool, 0700); e != nil {
		return e
	}
	queue := make(chan []byte, 256)
	done := make(chan error, 1)
	go func() {
		done <- drainSpoolQueueBounded(queue, persist, maxEvents, maxBytes)
	}()
	defer func() {
		close(queue)
		if writerErr := <-done; writerErr != nil {
			result = joinCaptureErrors(result, writerErr)
		}
	}()
	decoder := newCaptureFrameDecoder(config.MDNSRecordEvidenceV2)
	stats := NewCaptureStats()
	stats.Config = config
	if config.MDNSRecordEvidenceV2 {
		stats.DNSRecordEvidenceVersion = 2
	}
	statsWriter := newCaptureStatsWriter(func(snapshot *CaptureStats) error { return snapshot.persistSnapshot(spool) })
	publishStats := func() error {
		stats.FragmentDrops = decoder.FragmentDrops
		stats.DNSCache = decoder.DNS.captureStats()
		stats.recordQueue(len(queue), cap(queue), false)
		return statsWriter.submit(stats)
	}
	defer func() {
		// Retain the final counters even on overflow or another capture error.
		// Shutdown joins the writer; capture itself never waits on file writes.
		submitErr := publishStats()
		result = joinCaptureErrors(result, submitErr, statsWriter.close())
	}()
	pending := newCaptureCoalescer()
	lastFlush, lastStats := time.Now(), time.Now()
	flush := func() error {
		stats.recordQueue(len(queue), cap(queue), false)
		if pending.len() == 0 {
			return nil
		}
		b, e := json.Marshal(pending.events)
		if e != nil {
			return e
		}
		select {
		case queue <- b:
			stats.recordQueue(len(queue), cap(queue), false)
			pending.drain()
			lastFlush = time.Now()
			return nil
		default:
			stats.recordQueue(cap(queue), cap(queue), true)
			return fmt.Errorf("passive spool queue full; capture stopped to expose data loss")
		}
	}
	buffer := make([]byte, 65536)
	for ctx.Err() == nil {
		if err := statsWriter.err(); err != nil {
			return fmt.Errorf("passive capture statistics: %w", err)
		}
		select {
		case err := <-done:
			done <- err
			return err
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			if time.Since(lastFlush) >= coalesceWindow {
				if e = flush(); e != nil {
					return e
				}
			}
			if time.Since(lastStats) >= time.Second {
				if e = publishStats(); e != nil {
					return e
				}
				lastStats = time.Now()
			}
			continue
		}
		if err != nil {
			return err
		}

		decoded := decoder.Decode(buffer[:n], source, time.Now().UTC())
		stats.record(packetProtocol(buffer[:n]), len(decoded))
		events := filterCaptureEvents(decoded, allow)
		for _, event := range events {
			if !config.Enabled(event.SourceEventType) {
				continue
			}
			stats.recordEligible(event.SourceEventType, pending.add(event))
			if pending.len() >= 250 {
				if e = flush(); e != nil {
					return e
				}
			}
		}
		if time.Since(lastFlush) >= coalesceWindow {
			if e = flush(); e != nil {
				return e
			}
		}
		if time.Since(lastStats) >= time.Second {
			if e = publishStats(); e != nil {
				return e
			}
			lastStats = time.Now()
		}

	}
	if e = flush(); e != nil {
		return e
	}
	return ctx.Err()
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}
