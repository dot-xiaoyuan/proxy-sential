//go:build linux

package devicesignal

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

const maxFlowSYNBucketKeys = 10000
const maxTrackedFlowSYNKeys = 50000

// runFlowSYN has its own socket and source file. It never changes the router
// protocol or handshake collectors and never reads application payload.
func runFlowSYN(ctx context.Context, opts Options) error {
	ring, err := newFlowRing(opts.Interface)
	if err != nil {
		return err
	}
	defer ring.close()
	tracker := newStateChangeTracker[flowSYNKey](10 * time.Minute)
	tracker.limit = maxTrackedFlowSYNKeys
	responseTracker := newStateChangeTracker[flowSYNKey](10 * time.Minute)
	responseTracker.limit = maxTrackedFlowSYNKeys
	matcher := newFlowSYNMatcher(maxTrackedFlowSYNKeys)
	values := make(map[flowSYNKey]int)
	responses := make(map[flowSYNKey]int)
	coverageFrom := time.Now().UTC()
	bucket := coverageFrom
	var keyDrops, parseUnknown int
	flush := func(stopped bool) error {
		at := time.Now().UTC()
		if !at.Before(opts.CaptureScope.ValidUntil) {
			return fmt.Errorf("flow SYN capture scope expired before bucket flush")
		}
		bucket = at
		selected := tracker.filter(bucket, values)
		selectedResponses := responseTracker.filter(bucket, responses)
		if err := writeFlowSYNBucket(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, opts.CaptureScope, bucket, selected, selectedResponses); err != nil {
			return err
		}
		matcher.prune(at)
		received, dropped, freezes, known := ring.stats()
		coverage := sharedaccess.CoverageV2{
			SchemaVersion: "capture-coverage/v2", From: coverageFrom, To: at,
			KernelStatsKnown: known, Received: uint64(received), Dropped: uint64(dropped), QueueFreezes: uint64(freezes), KeyDrops: keyDrops + tracker.dropped + responseTracker.dropped + matcher.dropped,
			ParseUnknown: parseUnknown, Stopped: stopped,
		}
		if err := writeCaptureCoverage(opts.Output, opts.SensorID, opts.Interface, opts.CollectorInstanceID, "flow-syn-sidecar", opts.CaptureScope, coverage); err != nil {
			return err
		}
		if coverage.KeyDrops > 0 || coverage.Dropped > 0 || coverage.QueueFreezes > 0 {
			log.Printf("flow SYN capture incomplete: source=%s received=%d key_drops=%d kernel_drops=%d queue_freezes=%d", opts.Output, coverage.Received, coverage.KeyDrops, coverage.Dropped, coverage.QueueFreezes)
		}
		values = make(map[flowSYNKey]int)
		responses = make(map[flowSYNKey]int)
		coverageFrom = at
		bucket = at
		keyDrops, parseUnknown, tracker.dropped, responseTracker.dropped, matcher.dropped = 0, 0, 0, 0, 0
		return nil
	}
	ticker := time.NewTicker(opts.Bucket)
	defer ticker.Stop()
	consume := func(frame []byte) {
		observation, ok := parseFlowSYNFrame(frame)
		if !ok {
			parseUnknown++
			return
		}
		at := time.Now().UTC()
		if observation.Response {
			key, matched := matcher.matchResponse(observation, at)
			if !matched {
				return
			}
			if _, found := responses[key]; !found && len(responses) >= maxFlowSYNBucketKeys {
				keyDrops++
				return
			}
			responses[key]++
			return
		}
		if !flowSourceAllowed(observation.SourceIP, opts.SourceCIDRs) {
			return
		}
		key := flowSYNKey{SourceIP: observation.SourceIP, DestinationPort: observation.DestinationPort}
		if _, found := values[key]; !found && len(values) >= maxFlowSYNBucketKeys {
			keyDrops++
			return
		}
		if !matcher.recordInitial(observation, at) {
			// Retain the attempt but record that response correlation was incomplete.
			// The matcher capacity drop appears in the next coverage record.
		}
		values[key]++
	}
	for {
		processed := 0
		for processed < 8 {
			ready, readErr := ring.readReady(consume)
			if readErr != nil {
				return readErr
			}
			if !ready {
				break
			}
			processed++
		}
		select {
		case <-ctx.Done():
			return flush(true)
		case <-ticker.C:
			if err := flush(false); err != nil {
				return err
			}
		default:
			if processed == 0 {
				select {
				case <-ctx.Done():
					return flush(true)
				case <-ticker.C:
					if err := flush(false); err != nil {
						return err
					}
				default:
					if err := ring.wait(); err != nil {
						return err
					}
				}
			}
		}
	}
}

func flowSourceAllowed(source netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(source.Unmap()) {
			return true
		}
	}
	return false
}
