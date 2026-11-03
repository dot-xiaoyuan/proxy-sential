package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func passiveBufferTestConfig(segments int) passiveBufferConfig {
	return passiveBufferConfig{Segments: segments, Bytes: int64(segments) * streamlog.MaxSegmentBytes, MinFreeBytes: 1 << 30}
}

func passiveRecoveredIDs(count int) []string {
	ids := make([]string, count)
	for i := range ids {
		ids[i] = fmt.Sprintf("segment-%d", i)
	}
	return ids
}

func TestPassiveDurableBufferConfigRequiresCompleteBound(t *testing.T) {
	if hard, err := (passiveBufferConfig{}).validate(); err != nil || hard != 0 {
		t.Fatalf("default should retain compatibility mode: hard=%d err=%v", hard, err)
	}
	for _, config := range []passiveBufferConfig{
		{Segments: 600},
		{Segments: 600, Bytes: 600 * streamlog.MaxSegmentBytes},
		{Segments: 600, Bytes: 1 << 30, MinFreeBytes: 1 << 30},
	} {
		if _, err := config.validate(); err == nil {
			t.Fatalf("incomplete or undersized bound was accepted: %+v", config)
		}
	}
	if hard, err := passiveBufferTestConfig(600).validate(); err != nil || hard != 600 {
		t.Fatalf("complete bound rejected: hard=%d err=%v", hard, err)
	}
}

func TestPassiveDurableBufferLeavesRoomForEntireCaptureQueue(t *testing.T) {
	const capacity = 600
	stops := 0
	b, err := newPassiveDurableBuffer(context.Background(), passiveBufferTestConfig(capacity), t.TempDir(), passiveRecoveredIDs(341), func() { stops++ }, func() (uint64, error) { return 100 << 30, nil })
	if err != nil {
		t.Fatal(err)
	}
	if b.soft != capacity-passiveBufferDrainReserve || b.soft+discoveryCaptureQueueCapacityForTest() >= capacity {
		t.Fatalf("no drain headroom: soft=%d hard=%d", b.soft, b.hard)
	}
	b.add("trigger")
	if stops != 1 || !b.stoppedForLimit() {
		t.Fatalf("capture did not stop at soft limit: stops=%d snapshot=%+v", stops, b.snapshot())
	}
	for i := range 256 {
		b.add(fmt.Sprintf("already-queued-%d", i))
	}
	if got := b.snapshot().Segments; got > b.hard || got != b.soft+256 || stops != 1 {
		t.Fatalf("queued accepted batches exceeded durable bound: segments=%d stops=%d", got, stops)
	}
}

func discoveryCaptureQueueCapacityForTest() int { return passiveBufferDrainReserve - 2 }

func TestPassiveDurableBufferRecoveryWaitsForLowWater(t *testing.T) {
	config := passiveBufferTestConfig(600)
	b, err := newPassiveDurableBuffer(context.Background(), config, t.TempDir(), passiveRecoveredIDs(350), func() {}, func() (uint64, error) { return 100 << 30, nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.waitForCapture(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture reopened above high water: %v", err)
	}
	for i := range 180 {
		b.release(fmt.Sprintf("segment-%d", i))
	}
	if err := b.waitForCapture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.snapshot().PauseReason != "" {
		t.Fatal("capture did not clear pause after low water")
	}
}

func TestPassiveDurableBufferRejectsRecoveryAboveConfiguredLimit(t *testing.T) {
	if _, err := newPassiveDurableBuffer(context.Background(), passiveBufferTestConfig(600), t.TempDir(), passiveRecoveredIDs(601), func() {}, func() (uint64, error) { return 100 << 30, nil }); err == nil {
		t.Fatal("recovery silently accepted an unbounded journal backlog")
	}
}

func TestPassiveDurableBufferStopsWhenDiskHeadroomIsUncertain(t *testing.T) {
	stops := 0
	b, err := newPassiveDurableBuffer(context.Background(), passiveBufferTestConfig(600), t.TempDir(), nil, func() { stops++ }, func() (uint64, error) { return 0, errors.New("statfs failed") })
	if err != nil {
		t.Fatal(err)
	}
	b.add("durable-segment")
	if stops != 1 || b.snapshot().PauseReason != "disk_headroom_unavailable" {
		t.Fatalf("disk headroom failure was hidden: %+v stops=%d", b.snapshot(), stops)
	}
}

func TestPassiveDurableBacklogAppearsInBoundedMetrics(t *testing.T) {
	b, err := newPassiveDurableBuffer(context.Background(), passiveBufferTestConfig(600), t.TempDir(), []string{"private-segment-id"}, func() {}, func() (uint64, error) { return 100 << 30, nil })
	if err != nil {
		t.Fatal(err)
	}
	m := newPassiveStreamMetrics()
	m.buffer = b
	snapshot := m.snapshot("periodic", time.Now())
	if snapshot.DurableBacklog == nil || snapshot.DurableBacklog.Segments != 1 || snapshot.DurableBacklog.LimitSegments != 600 {
		t.Fatalf("durable backlog not visible: %+v", snapshot.DurableBacklog)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || string(raw) == "" {
		t.Fatalf("metrics encoding: %v", err)
	}
	if strings.Contains(string(raw), "private-segment-id") {
		t.Fatalf("metrics leaked a segment ID: %s", raw)
	}
}

func TestPassiveDurableBufferDoesNotRestartOnExternalStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stops := 0
	b, err := newPassiveDurableBuffer(ctx, passiveBufferTestConfig(600), t.TempDir(), passiveRecoveredIDs(341), func() { stops++ }, func() (uint64, error) { return 100 << 30, nil })
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	b.add("accepted-during-shutdown")
	if stops != 0 || b.stoppedForLimit() || b.snapshot().Segments != 342 {
		t.Fatalf("external shutdown was converted into buffer failure: stops=%d state=%+v", stops, b.snapshot())
	}
}

func TestPassiveDurableBufferStopCauseDistinguishesOperatorSignal(t *testing.T) {
	for _, externalFirst := range []bool{false, true} {
		signalCtx, signalCancel := context.WithCancel(context.Background())
		defer signalCancel()
		ctx, cancelCause := context.WithCancelCause(signalCtx)
		b, err := newPassiveDurableBuffer(ctx, passiveBufferTestConfig(600), t.TempDir(), passiveRecoveredIDs(341), func() { cancelCause(errPassiveBacklogPaused) }, func() (uint64, error) { return 100 << 30, nil })
		if err != nil {
			t.Fatal(err)
		}
		if externalFirst {
			signalCancel()
		}
		b.add("next")
		if !externalFirst {
			signalCancel()
		}
		if got := errors.Is(context.Cause(ctx), errPassiveBacklogPaused); got == externalFirst {
			t.Fatalf("externalFirst=%v cause=%v", externalFirst, context.Cause(ctx))
		}
	}
}

func TestPassiveDurablePauseKeepsJournalFailureVisible(t *testing.T) {
	ctx, cancelCause := context.WithCancelCause(context.Background())
	b, err := newPassiveDurableBuffer(ctx, passiveBufferTestConfig(600), t.TempDir(), nil, func() { cancelCause(errPassiveBacklogPaused) }, func() (uint64, error) { return 100 << 30, nil })
	if err != nil {
		t.Fatal(err)
	}
	cancelCause(errPassiveBacklogPaused)
	writeErr := errors.New("journal write failed")
	got := passiveCaptureResultError(ctx, b, errors.Join(context.Canceled, writeErr))
	if !errors.Is(got, errPassiveBacklogPaused) || !errors.Is(got, writeErr) {
		t.Fatalf("pause hid journal failure: %v", got)
	}
	if got := passiveCaptureResultError(ctx, b, context.Canceled); !errors.Is(got, errPassiveBacklogPaused) || errors.Is(got, writeErr) {
		t.Fatalf("ordinary paused capture returned wrong cause: %v", got)
	}
}

type testBufferedJournal struct{ id string }

func (j testBufferedJournal) LoadSource(string, string) (streamlog.SourceCursor, error) {
	return streamlog.SourceCursor{}, nil
}
func (j testBufferedJournal) AppendAndCommitPassive(streamlog.Segment) (string, error) {
	return j.id, nil
}

func TestPassiveBufferedCaptureJournalCountsOnlyDurableAppend(t *testing.T) {
	b, err := newPassiveDurableBuffer(context.Background(), passiveBufferTestConfig(600), t.TempDir(), nil, func() {}, func() (uint64, error) { return 100 << 30, nil })
	if err != nil {
		t.Fatal(err)
	}
	j := passiveBufferedCaptureJournal{journal: testBufferedJournal{id: "durable"}, buffer: b}
	if _, err := j.AppendAndCommitPassive(streamlog.Segment{}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.AppendAndCommitPassive(streamlog.Segment{}); err != nil {
		t.Fatal(err)
	}
	if b.snapshot().Segments != 1 {
		t.Fatalf("duplicate durable ID was counted twice: %+v", b.snapshot())
	}
	b.release("durable")
	if b.snapshot().Segments != 0 {
		t.Fatalf("finalization did not release quota: %+v", b.snapshot())
	}
}

func TestPassiveBufferedRecoveryEnqueuesBeyondLegacyQueue(t *testing.T) {
	journal, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const sourcePath = "packet://bond0/passive-buffer"
	if err := journal.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-buffer", Source: "passive-discovery", Path: sourcePath, FileID: "boot", ParserVersion: discovery.PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	for i := range 70 {
		segment := streamlog.Segment{Epoch: "fresh-buffer", Source: "passive-discovery", SourcePath: sourcePath,
			FileID: "boot", PreviousFileID: "boot", PreviousOffset: int64(i), StartOffset: int64(i), EndOffset: int64(i + 1),
			ParserVersion: discovery.PassiveStreamParserVersion, NeedsProjection: true,
			Events: []normalized.Event{{EventID: fmt.Sprintf("event-%d", i), Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Type: "discovery"}}}
		if _, err := journal.AppendAndCommitPassive(segment); err != nil {
			t.Fatalf("append segment %d: %v", i, err)
		}
	}
	recovered, err := journal.RecoverSource("passive-discovery", sourcePath)
	if err != nil || len(recovered) != 70 {
		t.Fatalf("recover: count=%d err=%v", len(recovered), err)
	}
	buffer, err := newPassiveDurableBuffer(context.Background(), passiveBufferTestConfig(600), journal.Directory(), recovered, func() {}, func() (uint64, error) { return 100 << 30, nil })
	if err != nil {
		t.Fatal(err)
	}
	queue := make(chan string, buffer.hard)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	metrics := newPassiveStreamMetrics()
	for _, id := range recovered {
		if err := enqueuePassiveLane(ctx, queue, id, streamlog.Projection, metrics); err != nil {
			t.Fatalf("durable recovery blocked at the old 64-slot projection queue: %v", err)
		}
	}
	for _, id := range recovered {
		if got := <-queue; got != id {
			t.Fatalf("recovery order changed: got=%s want=%s", got, id)
		}
	}
}
