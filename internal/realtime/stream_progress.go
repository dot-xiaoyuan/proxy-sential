package realtime

import (
	"context"
	"errors"
	"sync"
	"time"

	"proxy-sentinel/internal/streamlog"
)

type StreamSourceProgress struct {
	Epoch, AcceptedSegment, ArchivedSegment string
	AcceptedAt, ArchivedAt, OldestPendingAt time.Time
	PendingSegments                         int
	PendingBytes                            int64
	Blocker                                 streamlog.SourceBlocker
}

type streamSourceTracker struct {
	mu      sync.Mutex
	value   StreamSourceProgress
	pending map[string]streamlog.PendingSourceSegment
}

func newStreamSourceTracker(journal *streamlog.Journal, opts StreamRunOptions, source Source, recovered []string) (*streamSourceTracker, error) {
	if _, track := opts.ProgressSources[source.Path]; !track || opts.OnSourceProgress == nil {
		return nil, nil
	}
	cursor, err := journal.LoadSource(source.Kind, source.Path)
	if err != nil {
		return nil, err
	}
	blocker, err := journal.SourceBlocker(source.Kind, source.Path)
	if err != nil {
		return nil, err
	}
	if blocker.Epoch != cursor.Epoch {
		blocker = streamlog.SourceBlocker{}
	}
	tracker := &streamSourceTracker{value: StreamSourceProgress{Epoch: cursor.Epoch, Blocker: blocker}, pending: make(map[string]streamlog.PendingSourceSegment, len(recovered))}
	for _, id := range recovered {
		segment, err := journal.PendingSourceSegment(id)
		if err != nil {
			return nil, err
		}
		tracker.accept(id, segment)
	}
	return tracker, nil
}

func (t *streamSourceTracker) block(journal *streamlog.Journal, source Source, id, stage string, cause error) error {
	if t == nil {
		return cause
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.value.Blocker.Reason != "" {
		return cause
	}
	t.value.Blocker = streamlog.SourceBlocker{Epoch: t.value.Epoch, SegmentID: id, Stage: stage, Reason: streamFailureReason(cause), FirstAt: time.Now().UTC()}
	return errors.Join(cause, journal.RecordSourceBlocker(source.Kind, source.Path, t.value.Blocker))
}

func (t *streamSourceTracker) report(ctx context.Context, opts StreamRunOptions, source Source) {
	if t == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := opts.OnSourceProgress(ctx, source, t.snapshot()); err != nil && !errors.Is(err, context.Canceled) {
		opts.OnSourceError(source, err)
	}
}

func (t *streamSourceTracker) reportUntilCanceled(ctx context.Context, opts StreamRunOptions, source Source) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		t.report(ctx, opts, source)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (t *streamSourceTracker) recordAccepted(journal *streamlog.Journal, id string, report func(error)) {
	if t == nil {
		return
	}
	segment, err := journal.PendingSourceSegment(id)
	if err != nil {
		report(err)
		return
	}
	t.accept(id, segment)
}

func (t *streamSourceTracker) finished(journal *streamlog.Journal, source Source, id string, report func(error)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, id)
	if t.value.Blocker.Reason != "" && t.value.Blocker.SegmentID == id {
		if err := journal.RecordSourceBlocker(source.Kind, source.Path, streamlog.SourceBlocker{}); err != nil {
			report(err)
			return
		}
		t.value.Blocker = streamlog.SourceBlocker{}
	}
}

func (t *streamSourceTracker) accept(id string, segment streamlog.PendingSourceSegment) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending[id] = segment
	if !segment.AcceptedAt.Before(t.value.AcceptedAt) {
		t.value.AcceptedAt, t.value.AcceptedSegment = segment.AcceptedAt, id
	}
	if segment.Archived && !segment.AcceptedAt.Before(t.value.ArchivedAt) {
		t.value.ArchivedAt, t.value.ArchivedSegment = segment.AcceptedAt, id
	}
}

func (t *streamSourceTracker) archive(id string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !at.Before(t.value.ArchivedAt) {
		t.value.ArchivedAt, t.value.ArchivedSegment = at, id
	}
}

func (t *streamSourceTracker) snapshot() StreamSourceProgress {
	t.mu.Lock()
	defer t.mu.Unlock()
	value := t.value
	value.PendingSegments = len(t.pending)
	for _, pending := range t.pending {
		value.PendingBytes += pending.Bytes
		if value.OldestPendingAt.IsZero() || pending.AcceptedAt.Before(value.OldestPendingAt) {
			value.OldestPendingAt = pending.AcceptedAt
		}
	}
	return value
}
