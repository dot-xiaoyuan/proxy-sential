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

const streamCaptureFlushWindow = 4 * time.Second

// Capture spools standard events on a separate goroutine; packet reads never wait on database work.
func Capture(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix) error {
	return CaptureConfigured(ctx, iface, spool, source, allow, DefaultCollectionConfig())
}
func CaptureConfigured(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix, config CollectionConfig) (result error) {
	return captureConfiguredWithPersist(ctx, iface, spool, source, allow, config, 2000, 8<<20, captureFlushEvents, 100*time.Millisecond, 0, false, false, func(b []byte) error {
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
	maxEvents, maxBytes, err := passiveStreamCaptureBudget(config)
	if err != nil {
		return err
	}
	return captureConfiguredWithPersist(ctx, iface, statsDir, source, allow, config, maxEvents, maxBytes, maxEvents, streamCaptureFlushWindow, 500*time.Millisecond, true, true, func(b []byte) error {
		return persistPassiveStreamCaptureBatchWithScheme(ctx, journal, source, scope, passiveStreamKeyScheme(config), onSegment, b)
	})
}

func passiveStreamCaptureBudget(config CollectionConfig) (int, int, error) {
	maxEvents := config.PassiveSegmentMaxEvents
	if maxEvents == 0 {
		maxEvents = streamlog.MaxSegmentEvents
	}
	if maxEvents != streamlog.MaxSegmentEvents && maxEvents != streamlog.MaxPassiveSegmentEvents {
		return 0, 0, fmt.Errorf("invalid passive segment event limit: %d", maxEvents)
	}
	maxBytes := 1 << 20
	if maxEvents == streamlog.MaxPassiveSegmentEvents {
		maxBytes = 2 << 20
	}
	return maxEvents, maxBytes, nil
}

func persistPassiveStreamCaptureBatch(ctx context.Context, journal PassiveStreamJournal, source Source, scope *normalized.CaptureScope, compactKeys bool, onSegment func(CapturedSegment) error, raw []byte) error {
	scheme := passiveEventKeyLegacy
	if compactKeys {
		scheme = passiveEventKeyStream2
	}
	return persistPassiveStreamCaptureBatchWithScheme(ctx, journal, source, scope, scheme, onSegment, raw)
}

func persistPassiveStreamCaptureBatchWithScheme(ctx context.Context, journal PassiveStreamJournal, source Source, scope *normalized.CaptureScope, scheme passiveEventKeyScheme, onSegment func(CapturedSegment) error, raw []byte) error {
	var events []normalized.Event
	if err := json.Unmarshal(raw, &events); err != nil {
		return err
	}
	// Capture stops on cancellation, but its accepted in-memory queue still
	// needs to reach the journal before the worker exits. Recovery will enqueue
	// these segments on the next start.
	captured, err := appendPassiveStreamBatchWithScheme(context.WithoutCancel(ctx), journal, source, scope, events, scheme)
	if err != nil {
		return err
	}
	if onSegment == nil || ctx.Err() != nil {
		return nil
	}
	if err := onSegment(captured); err != nil {
		// Cancellation can race with an in-flight lane enqueue. The segment is
		// already durable, and startup recovery will re-enqueue every lane.
		if ctx.Err() != nil && captureCancellationOnly(err) {
			return nil
		}
		return err
	}
	return nil
}

func captureConfiguredWithPersist(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix, config CollectionConfig, maxEvents, maxBytes, flushEvents int, flushWindow, gatherWindow time.Duration, splitOversized, drainOnCancel bool, persist func([]byte) error) (result error) {
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
	queue := make(chan []byte, PassiveCaptureQueueCapacity)
	done := make(chan error, 1)
	go func() {
		done <- drainSpoolQueueBoundedWindow(queue, persist, maxEvents, maxBytes, gatherWindow)
	}()
	defer func() {
		close(queue)
		if writerErr := <-done; writerErr != nil {
			result = joinCaptureErrors(result, writerErr)
		}
	}()
	decoder := newCaptureFrameDecoder(config.MDNSRecordEvidenceV2, allow...)
	stats := NewCaptureStats()
	stats.Config = config
	if config.Stream3PassiveEventKeys {
		stats.EventKeyVersion = 3
	} else if config.CompactPassiveEventKeys {
		stats.EventKeyVersion = 2
	}
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
	arpDedup := newARPDedupCache(config.PassiveARPDedupWindow)
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
		batches := [][]byte{b}
		if splitOversized && len(b) > maxBytes {
			batches, e = splitCaptureBatch(b, maxBytes)
			if e != nil {
				return e
			}
		}
		for _, batch := range batches {
			if err := enqueueCaptureBatch(ctx, queue, done, batch, stats, drainOnCancel); err != nil {
				return err
			}
		}
		pending.drain()
		lastFlush = time.Now()
		return nil
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
			if time.Since(lastFlush) >= flushWindow {
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
			if !arpDedup.allow(event) {
				continue
			}
			stats.recordEligible(event.SourceEventType, pending.add(event))
			if pending.len() >= flushEvents {
				if e = flush(); e != nil {
					return e
				}
			}
		}
		if time.Since(lastFlush) >= flushWindow {
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

func enqueueCaptureBatch(ctx context.Context, queue chan []byte, done chan error, batch []byte, stats *CaptureStats, drainOnCancel bool) error {
	if drainOnCancel && ctx.Err() != nil {
		// The final coalesced batch still belongs to this capture. Once capture
		// has stopped, wait for the writer to make room instead of declaring
		// overflow while it is draining the already queued batches.
		select {
		case queue <- batch:
			stats.recordQueue(len(queue), cap(queue), false)
			return nil
		case writerErr := <-done:
			done <- writerErr // The deferred join still owns the writer result.
			if writerErr == nil {
				return fmt.Errorf("passive spool writer exited before final capture batch")
			}
			return writerErr
		}
	}
	select {
	case queue <- batch:
		stats.recordQueue(len(queue), cap(queue), false)
		return nil
	default:
		stats.recordQueue(cap(queue), cap(queue), true)
		return fmt.Errorf("passive spool queue full; capture stopped to expose data loss")
	}
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}
