package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"sync"
	"syscall"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/streamlog"
)

var errPassiveBacklogPaused = errors.New("passive capture paused at durable backlog limit")

// This mode keeps only bounded segment IDs in memory. Bodies and independent
// lane acknowledgements remain in the existing journal. Budget each pending
// segment at its maximum body size, so a bytes limit never undercounts a body.
type passiveBufferConfig struct {
	Segments     int
	Bytes        int64
	MinFreeBytes int64
}

type passiveBacklogSnapshot struct {
	Segments       int       `json:"segments"`
	LimitSegments  int       `json:"limit_segments"`
	ReservedBytes  int64     `json:"reserved_bytes"`
	LimitBytes     int64     `json:"limit_bytes"`
	FreeBytes      uint64    `json:"free_bytes"`
	FreeCheckedAt  time.Time `json:"free_checked_at,omitempty"`
	MinFreeBytes   int64     `json:"min_free_bytes"`
	PauseReason    string    `json:"pause_reason,omitempty"`
	PauseCount     uint64    `json:"pause_count"`
	RecoveredCount int       `json:"recovered_count"`
}

type passiveDurableBuffer struct {
	mu        sync.Mutex
	config    passiveBufferConfig
	hard      int
	soft      int
	low       int
	pending   map[string]struct{}
	recovered int
	free      uint64
	checkedAt time.Time
	reason    string
	pauses    uint64
	draining  bool
	triggered bool
	ctx       context.Context
	stop      func()
	freeBytes func() (uint64, error)
}

// The queued packet reader can be one batch ahead of its writer. Reserve the
// full queue plus the writer and final partial batch before pausing capture.
const passiveBufferDrainReserve = discovery.PassiveCaptureQueueCapacity + 2

func (c passiveBufferConfig) validate() (int, error) {
	if c.Segments == 0 && c.Bytes == 0 && c.MinFreeBytes == 0 {
		return 0, nil // compatibility mode, unchanged 64-ID lane queues
	}
	if c.Segments <= passiveBufferDrainReserve*2 || c.Segments > 16384 ||
		c.Bytes <= int64(passiveBufferDrainReserve*2)*streamlog.MaxSegmentBytes ||
		c.Bytes > 1<<50 || c.MinFreeBytes < 1<<30 || c.MinFreeBytes > math.MaxInt64-int64(passiveBufferDrainReserve*streamlog.MaxSegmentBytes) {
		return 0, errors.New("durable passive buffer needs 517-16384 segments, over 2 GiB byte budget and at least 1 GiB free-disk reserve")
	}
	hard := min(c.Segments, int(c.Bytes/streamlog.MaxSegmentBytes))
	if hard <= passiveBufferDrainReserve*2 {
		return 0, errors.New("durable passive buffer has no drain and resume headroom")
	}
	return hard, nil
}

func passiveJournalFreeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil
}

func newPassiveDurableBuffer(ctx context.Context, config passiveBufferConfig, path string, recovered []string, stop func(), freeBytes func() (uint64, error)) (*passiveDurableBuffer, error) {
	hard, err := config.validate()
	if err != nil || hard == 0 {
		return nil, err
	}
	if ctx == nil || stop == nil {
		return nil, errors.New("durable passive buffer needs a context and stop function")
	}
	if len(recovered) > hard {
		return nil, fmt.Errorf("durable passive recovery has %d segments above configured %d limit; keep the prior limit or drain the existing journal", len(recovered), hard)
	}
	if freeBytes == nil {
		freeBytes = func() (uint64, error) { return passiveJournalFreeBytes(path) }
	}
	pending := make(map[string]struct{}, len(recovered))
	for _, id := range recovered {
		if id == "" {
			return nil, errors.New("durable passive buffer recovered an empty segment ID")
		}
		if _, duplicate := pending[id]; duplicate {
			return nil, fmt.Errorf("durable passive buffer recovered duplicate segment %s", id)
		}
		pending[id] = struct{}{}
	}
	b := &passiveDurableBuffer{config: config, hard: hard, soft: hard - passiveBufferDrainReserve,
		low: (hard - passiveBufferDrainReserve) / 2, pending: pending, recovered: len(recovered), stop: stop, freeBytes: freeBytes, ctx: ctx}
	if free, err := freeBytes(); err == nil {
		b.free = free
		b.checkedAt = time.Now().UTC()
	}
	return b, nil
}

func (b *passiveDurableBuffer) add(id string) {
	free, err := b.freeBytes()
	b.mu.Lock()
	if _, exists := b.pending[id]; !exists {
		b.pending[id] = struct{}{}
	}
	if err == nil {
		b.free = free
		b.checkedAt = time.Now().UTC()
	}
	reason := ""
	if len(b.pending) >= b.soft {
		reason = "segment_or_byte_limit"
	} else if err != nil {
		reason = "disk_headroom_unavailable"
	} else if free <= uint64(b.config.MinFreeBytes)+uint64(passiveBufferDrainReserve*streamlog.MaxSegmentBytes) {
		reason = "disk_headroom"
	}
	firstPause := reason != "" && b.reason == "" && b.ctx.Err() == nil
	if firstPause {
		b.reason = reason
		b.pauses++
		b.triggered = true
		b.draining = true
	}
	count := len(b.pending)
	b.mu.Unlock()
	if firstPause {
		log.Printf("passive durable backlog paused capture: reason=%s segments=%d capacity=%d reserved_bytes=%d free_bytes=%d", reason, count, b.hard, int64(count)*streamlog.MaxSegmentBytes, free)
		b.stop()
	}
}

func (b *passiveDurableBuffer) release(id string) {
	b.mu.Lock()
	delete(b.pending, id)
	b.mu.Unlock()
}

func (b *passiveDurableBuffer) snapshot() passiveBacklogSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return passiveBacklogSnapshot{Segments: len(b.pending), LimitSegments: b.hard,
		ReservedBytes: int64(len(b.pending)) * streamlog.MaxSegmentBytes, LimitBytes: b.config.Bytes,
		FreeBytes: b.free, FreeCheckedAt: b.checkedAt, MinFreeBytes: b.config.MinFreeBytes, PauseReason: b.reason,
		PauseCount: b.pauses, RecoveredCount: b.recovered}
}

func (b *passiveDurableBuffer) stoppedForLimit() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.triggered
}

// Recovery enqueues every durable segment before reopening the packet socket.
// A high-water restart waits for a low watermark so it cannot restart capture
// just to refill the same full journal seconds later.
func (b *passiveDurableBuffer) waitForCapture(ctx context.Context) error {
	lastReport := time.Time{}
	for {
		free, err := b.freeBytes()
		b.mu.Lock()
		count := len(b.pending)
		if err == nil {
			b.free = free
			b.checkedAt = time.Now().UTC()
		}
		if count >= b.soft {
			b.draining = true
		}
		needDrain := b.draining
		if needDrain && b.reason == "" {
			b.reason = "recovery_backlog"
			b.pauses++
		}
		diskReady := err == nil && free > uint64(b.config.MinFreeBytes)+uint64(passiveBufferDrainReserve*streamlog.MaxSegmentBytes)
		ready := diskReady && (!needDrain || count <= b.low)
		if ready {
			b.reason = ""
			b.draining = false
		} else if !diskReady && b.reason == "" {
			b.reason = "disk_headroom"
			b.pauses++
		}
		reason := b.reason
		b.mu.Unlock()
		if ready {
			return nil
		}
		if time.Since(lastReport) >= 30*time.Second {
			log.Printf("passive durable backlog waiting before capture: reason=%s segments=%d low_water=%d free_bytes=%d", reason, count, b.low, free)
			lastReport = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

type passiveBufferedCaptureJournal struct {
	journal discovery.PassiveStreamJournal
	buffer  *passiveDurableBuffer
}

func (j passiveBufferedCaptureJournal) LoadSource(source, path string) (streamlog.SourceCursor, error) {
	return j.journal.LoadSource(source, path)
}

func (j passiveBufferedCaptureJournal) AppendAndCommitPassive(segment streamlog.Segment) (string, error) {
	id, err := j.journal.AppendAndCommitPassive(segment)
	if err == nil {
		j.buffer.add(id)
	}
	return id, err
}
