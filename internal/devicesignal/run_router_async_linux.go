//go:build linux

package devicesignal

import (
	"context"
	"fmt"
	"log"
	"proxy-sentinel/internal/sharedaccess"
	"syscall"
	"time"
)

// One completed bucket, the bucket being written, and the active receive
// bucket bound the in-process handoff. A full queue blocks reception; the
// following PACKET_STATISTICS interval then reports any kernel drops.
const routerCaptureQueuedBuckets = 1

type routerCaptureSnapshot struct {
	bucket   time.Time
	queuedAt time.Time
	state    *captureBucket
	coverage sharedaccess.CoverageV2
}

func runRouterCaptureLoop(ctx context.Context, opts Options, fd int, boundAt time.Time, previous sharedaccess.CoverageV2, previousKnown bool, priorErr error) (result error) {
	state := newCaptureBucket()
	tracker := newStateChangeTracker[packetBucketKey](opts.StateLiveness)
	controlTracker := newStateChangeTracker[string](opts.StateLiveness)
	writeCoverage := func(coverage sharedaccess.CoverageV2) error {
		if err := writeCaptureCoverage(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, "packet-sidecar", opts.CaptureScope, coverage); err != nil {
			return err
		}
		return saveCaptureCoverageCheckpoint(opts.Output, opts.SensorID, opts.CollectorInstanceID, coverage)
	}
	setupReceived, setupDropped, setupKnown := packetCaptureStats(fd)
	coverageFrom := time.Now().UTC()
	startup, continuityKnown := routerStartupCoverage(boundAt, coverageFrom, previous, previousKnown, priorErr, setupReceived, setupDropped)
	firstCoverageUnknown := !continuityKnown
	if priorErr != nil {
		log.Printf("device signal capture continuity unknown: previous coverage lookup failed: %v; setup_received=%d setup_dropped=%d setup_stats_known=%t", priorErr, setupReceived, setupDropped, setupKnown)
	} else if !previousKnown {
		log.Printf("device signal capture continuity unknown: no previous durable coverage for instance=%s; setup_received=%d setup_dropped=%d setup_stats_known=%t", opts.CollectorInstanceID, setupReceived, setupDropped, setupKnown)
	} else if !continuityKnown {
		log.Printf("device signal capture continuity unknown: previous coverage ended at or after new start")
	}
	// The socket is already bound. Persist setup counters in a stopped interval
	// whether or not the previous durable coverage could be located.
	if err := writeCoverage(startup); err != nil {
		return fmt.Errorf("persist capture restart gap: %w", err)
	}
	bucket := coverageFrom.Truncate(opts.Bucket)
	lastWrittenBucket := bucket
	write := func(item routerCaptureSnapshot) error {
		started := time.Now()
		if item.state.droppedPacketKeys > 0 {
			log.Printf("device signal bucket reached key limit; dropped_new_keys=%d limit=%d", item.state.droppedPacketKeys, maxPacketBucketKeys)
		}
		selectedPackets := tracker.filter(item.bucket, item.state.packets)
		if err := writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, "packet-sidecar", opts.CaptureScope, item.bucket, selectedPackets); err != nil {
			return err
		}
		selectedControls := selectControls(controlTracker, item.bucket, item.state.controls)
		for key, signal := range selectedControls {
			if signal.Kind != "ieee1905_client_snapshot" && signal.Kind != "ieee1905_client_association" {
				continue
			}
			// The tracker compares protocol content only; coverage is output metadata.
			payload := make(map[string]any, len(signal.Payload)+1)
			for name, value := range signal.Payload {
				payload[name] = value
			}
			payload["capture_coverage"] = item.coverage
			signal.Payload = payload
			selectedControls[key] = signal
		}
		if err := writeControlBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, item.bucket, selectedControls); err != nil {
			return err
		}
		if err := writeCoverage(item.coverage); err != nil {
			return err
		}
		lastWrittenBucket = item.bucket
		if elapsed := time.Since(started); elapsed >= time.Second {
			log.Printf("device signal bucket write: duration=%s queued=%s packets=%d controls=%d", elapsed, started.Sub(item.queuedAt), len(selectedPackets), len(selectedControls))
		}
		return nil
	}
	finish := func() error {
		// State held across buckets was previously emitted on a clean stop.
		if held := tracker.pending(); len(held) > 0 {
			if err := writePacketBucketWithSource(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, "packet-sidecar", opts.CaptureScope, lastWrittenBucket, held); err != nil {
				return err
			}
		}
		// The socket remains live while already detached buckets are persisted.
		// Account for that final interval instead of silently losing shutdown drops.
		end := time.Now().UTC()
		received, dropped, known := packetCaptureStats(fd)
		return writeCoverage(sharedaccess.CoverageV2{
			SchemaVersion: "capture-coverage/v2", From: coverageFrom, To: end,
			KernelStatsKnown: known, Received: uint64(received), Dropped: uint64(dropped), Stopped: true,
		})
	}
	writer := newBoundedCaptureWriter(routerCaptureQueuedBuckets, write, finish)
	defer func() {
		if err := writer.closeAndWait(); result == nil {
			result = err
		}
	}()
	flush := func() error {
		end := time.Now().UTC()
		received, dropped, known := packetCaptureStats(fd)
		item := routerCaptureSnapshot{
			bucket: bucket, queuedAt: end, state: state,
			coverage: sharedaccess.CoverageV2{
				SchemaVersion: "capture-coverage/v2", From: coverageFrom, To: end,
				KernelStatsKnown: known && !firstCoverageUnknown, Received: uint64(received), Dropped: uint64(dropped), Stopped: firstCoverageUnknown,
				ParseUnknown: state.controlParseFailures,
				KeyDrops:     state.controlKeyDrops + state.droppedPacketKeys,
			},
		}
		waitStarted := time.Now()
		if err := writer.submit(item); err != nil {
			return fmt.Errorf("write router capture bucket: %w", err)
		}
		if wait := time.Since(waitStarted); wait >= 100*time.Millisecond {
			log.Printf("device signal receive backpressure: queued_buckets=%d wait=%s", cap(writer.queue), wait)
		}
		coverageFrom = end
		firstCoverageUnknown = false
		bucket = end.Truncate(opts.Bucket)
		state = newCaptureBucket()
		return nil
	}
	ticker := time.NewTicker(opts.Bucket)
	defer ticker.Stop()
	buffer := make([]byte, 65536)
	for {
		if err := writer.failed(); err != nil {
			return fmt.Errorf("write router capture bucket: %w", err)
		}
		processed := 0
		for processed < 4096 {
			n, _, recvErr := syscall.Recvfrom(fd, buffer, 0)
			if recvErr == syscall.EAGAIN || recvErr == syscall.EWOULDBLOCK {
				break
			}
			if recvErr != nil {
				_ = flush()
				return recvErr
			}
			processed++
			state.addFrame(buffer[:n], opts.CaptureScope)
		}
		select {
		case <-ctx.Done():
			return flush()
		case <-ticker.C:
			if err := flush(); err != nil {
				return err
			}
		default:
			if processed == 0 {
				select {
				case <-ctx.Done():
					return flush()
				case <-ticker.C:
					if err := flush(); err != nil {
						return err
					}
				case <-writer.done:
					return fmt.Errorf("write router capture bucket: %w", writer.err)
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
	}
}
