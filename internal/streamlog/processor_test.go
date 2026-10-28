package streamlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSourceBackedRawIsReadOnlyByArchiveLane(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("bounded zeek source bytes\n")
	segment := testSegment()
	segment.Source = "zeek-dhcp-binding"
	segment.SourceBackedRaw = true
	segment.Raw = raw
	segment.EndOffset = segment.StartOffset + int64(len(raw))
	sum := sha256.Sum256(raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	loads := 0
	j.SetRawResolver(func(Segment) ([]byte, error) {
		loads++
		return append([]byte(nil), raw...), nil
	})
	id := appendCommitted(t, j, segment)
	loads = 0
	p := Processor{Journal: j, Writer: &fakeLaneWriter{}}
	if err := p.DrainLane(context.Background(), id, Projection); err != nil {
		t.Fatal(err)
	}
	if loads != 0 {
		t.Fatalf("projection reread source raw %d times", loads)
	}
	if err := p.DrainLane(context.Background(), id, Archive); err != nil {
		t.Fatal(err)
	}
	if loads != 1 {
		t.Fatalf("archive should verify raw once, got %d reads", loads)
	}
	if err := p.DrainLane(context.Background(), id, Archive); err != nil || loads != 1 {
		t.Fatalf("acknowledged archive reread source raw: reads=%d err=%v", loads, err)
	}
	if err := p.DrainLane(context.Background(), id, Search); err != nil {
		t.Fatal(err)
	}
	if loads != 1 {
		t.Fatalf("search reread source raw %d times", loads)
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if loads != 1 {
		t.Fatalf("finalizer reread source raw %d times", loads)
	}
}

type fakeLaneWriter struct {
	archiveWrites   int
	archiveChecks   int
	searchWrites    int
	projects        int
	failArchiveOnce bool
}

type mutateAfterArchiveWriter struct {
	fakeLaneWriter
	path string
}

func (w *mutateAfterArchiveWriter) WriteBody(_ context.Context, _ string, segment Segment) error {
	if len(segment.Events) != 1 || segment.Events[0].EventID != "event-1" {
		return errors.New("sink did not receive verified event")
	}
	return os.WriteFile(w.path, []byte("corrupt after delivery"), 0600)
}

func TestVerifiedAckKeepsCorruptJournalBodyForRecovery(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	p := Processor{Journal: j, Writer: &mutateAfterArchiveWriter{path: j.path(id, ".segment")}}
	if err := p.DrainLane(context.Background(), id, Archive); err != nil {
		t.Fatalf("a completed sink write should retain its durable acknowledgement: %v", err)
	}
	status, err := j.loadPendingStatus(id)
	if err != nil || status.Acks[Archive] != Acked {
		t.Fatalf("ack lost: %+v %v", status.Acks, err)
	}
	if _, err := j.Load(id); err == nil {
		t.Fatal("corrupt journal body was accepted")
	}
	if _, err := os.Stat(j.path(id, ".segment")); err != nil {
		t.Fatalf("corrupt body removed: %v", err)
	}
}

func TestVerifiedAckRejectsDifferentContentProof(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	if err := j.setAckWithProof(id, Archive, Attempted, strings.Repeat("0", 64)); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("mismatched proof was accepted: %v", err)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[Archive] != Pending {
		t.Fatalf("mismatched proof changed state: %+v %v", state.Acks, err)
	}
}

type rejectingPreflightWriter struct{ fakeLaneWriter }

func (*rejectingPreflightWriter) Preflight(lane Lane, _ Segment) error {
	if lane == Archive {
		return errors.New("invalid local archive input")
	}
	return nil
}

func TestProcessorRejectsLocalArchiveBeforeDurableAttempt(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &rejectingPreflightWriter{}
	if err := (Processor{Journal: j, Writer: w}).DrainLane(context.Background(), id, Archive); err == nil {
		t.Fatal("invalid archive input was accepted")
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[Archive] != Pending || w.archiveWrites != 0 {
		t.Fatalf("local validation stranded an ambiguous sink attempt: %+v writes=%d err=%v", state.Acks, w.archiveWrites, err)
	}
}

type expireAfterPreparation struct{ checks int }

func (c *expireAfterPreparation) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *expireAfterPreparation) Done() <-chan struct{}       { return nil }
func (c *expireAfterPreparation) Err() error {
	c.checks++
	if c.checks > 1 {
		return context.DeadlineExceeded
	}
	return nil
}
func (c *expireAfterPreparation) Value(any) any { return nil }

func TestProcessorRetriesWhenLocalAttemptSyncExhaustsBudgetBeforeSend(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &fakeLaneWriter{}
	p := Processor{Journal: j, Writer: w}
	if err := p.DrainLane(&expireAfterPreparation{}, id, Archive); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected local preparation timeout, got %v", err)
	}
	if w.archiveWrites != 0 {
		t.Fatal("sink called after local budget expired")
	}
	j, err = Open(j.Directory())
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[Archive] != Pending {
		t.Fatalf("unsent attempt stayed ambiguous across restart: %+v %v", state.Acks, err)
	}
	p.Journal = j
	if err := p.DrainLane(context.Background(), id, Archive); err != nil || w.archiveWrites != 1 {
		t.Fatalf("verified unsent write was not retried: %v %+v", err, w)
	}
}

type finalizingWriter struct {
	fakeLaneWriter
	finalizations int
	failOnce      bool
	minimumBudget time.Duration
}

func (w *finalizingWriter) FinalizeSegment(ctx context.Context, _ string, _ Segment) error {
	w.finalizations++
	if w.minimumBudget > 0 {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < w.minimumBudget {
			return errors.New("finalization reused the short sink budget")
		}
	}
	if w.failOnce {
		w.failOnce = false
		return errors.New("confirmation state unavailable")
	}
	return nil
}

func TestProcessorUsesIndependentFinalizationBudget(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &finalizingWriter{minimumBudget: time.Second}
	p := Processor{Journal: j, Writer: w, SinkTimeout: 100 * time.Millisecond, FinalizeTimeout: 2 * time.Second}
	if err := p.Drain(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if w.finalizations != 1 {
		t.Fatalf("finalizations=%d", w.finalizations)
	}
}

func TestProcessorRetainsSegmentUntilArchiveStatusFinalized(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &finalizingWriter{failOnce: true}
	p := Processor{Journal: j, Writer: w}
	if err := p.Drain(context.Background(), id); err == nil {
		t.Fatal("failed status finalization released source")
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[Archive] != Acked || state.Acks[Search] != Acked || state.Acks[Projection] != Acked {
		t.Fatalf("sink acks lost: %+v %v", state.Acks, err)
	}
	if err := p.Drain(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if w.finalizations != 2 || w.archiveWrites != 1 || w.projects != 1 {
		t.Fatalf("lanes reran after finalization failure: %+v", w)
	}
	if _, err := j.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed segment retained: %v", err)
	}
}

type blockedArchiveWriter struct {
	fakeLaneWriter
	archiveEntered chan struct{}
	releaseArchive chan struct{}
	projected      chan struct{}
}

func (w *blockedArchiveWriter) WriteBody(ctx context.Context, _ string, _ Segment) error {
	close(w.archiveEntered)
	select {
	case <-w.releaseArchive:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *blockedArchiveWriter) Project(context.Context, string, Segment) error {
	close(w.projected)
	return nil
}

func TestProcessorProjectsWhileArchiveIsBlocked(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &blockedArchiveWriter{archiveEntered: make(chan struct{}), releaseArchive: make(chan struct{}), projected: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- (Processor{Journal: j, Writer: w}).Drain(context.Background(), id) }()
	select {
	case <-w.archiveEntered:
	case <-time.After(time.Second):
		t.Fatal("archive did not start")
	}
	select {
	case <-w.projected:
	case <-time.After(time.Second):
		close(w.releaseArchive)
		t.Fatal("projection was delayed by archive")
	}
	deadline := time.Now().Add(time.Second)
	for {
		state, err := j.Load(id)
		if err == nil && state.Acks[Projection] == Acked {
			break
		}
		if time.Now().After(deadline) {
			close(w.releaseArchive)
			t.Fatalf("projection not durably acknowledged: %+v %v", state.Acks, err)
		}
		time.Sleep(time.Millisecond)
	}
	close(w.releaseArchive)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIndependentLaneAdvancesLaterProjectionWhileEarlierArchiveIsBlocked(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := appendCommitted(t, j, testSegment())
	secondSegment := testSegment()
	secondSegment.SourcePath = "/logs/mdns.log"
	secondSegment.FileID = "device-2"
	secondSegment.PreviousFileID = "device-2"
	second := appendCommitted(t, j, secondSegment)
	w := &blockedArchiveWriter{archiveEntered: make(chan struct{}), releaseArchive: make(chan struct{}), projected: make(chan struct{})}
	p := Processor{Journal: j, Writer: w}
	archiveDone := make(chan error, 1)
	go func() { archiveDone <- p.DrainLane(context.Background(), first, Archive) }()
	select {
	case <-w.archiveEntered:
	case <-time.After(time.Second):
		t.Fatal("earlier archive did not block")
	}
	if err := p.DrainLane(context.Background(), second, Projection); err != nil {
		close(w.releaseArchive)
		t.Fatal(err)
	}
	state, err := j.Load(second)
	if err != nil || state.Acks[Projection] != Acked {
		close(w.releaseArchive)
		t.Fatalf("later projection waited behind archive: %+v %v", state.Acks, err)
	}
	close(w.releaseArchive)
	if err := <-archiveDone; err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeAfterLanesKeepsSegmentUntilAllAcks(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	p := Processor{Journal: j, Writer: &fakeLaneWriter{}}
	if err := p.DrainLane(context.Background(), id, Projection); err != nil {
		t.Fatal(err)
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("unarchived event released: %v", err)
	}
	if err := p.DrainLane(context.Background(), id, Search); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("search ran before body: %v", err)
	}
	for _, lane := range []Lane{Archive, Search} {
		if err := p.DrainLane(context.Background(), id, lane); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fully acknowledged event still retained: %v", err)
	}
}

func TestPendingLanesAvoidBodyReadButVerifyBeforeUseAndRelease(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	path := j.path(id, ".segment")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("broken segment"), 0600); err != nil {
		t.Fatal(err)
	}
	w := &fakeLaneWriter{}
	p := Processor{Journal: j, Writer: w}
	if err := p.DrainLane(context.Background(), id, Search); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("search should wait for archive without reading body: %v", err)
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("finalization should wait for lanes without reading body: %v", err)
	}
	if err := p.DrainLane(context.Background(), id, Archive); err == nil || w.archiveWrites != 0 {
		t.Fatalf("corrupt body reached archive: err=%v writes=%d", err, w.archiveWrites)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	for _, lane := range []Lane{Archive, Search, Projection} {
		if err := p.DrainLane(context.Background(), id, lane); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("broken segment"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); err == nil {
		t.Fatal("finalizer released a corrupt body")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("corrupt segment was removed: %v", err)
	}
}

func BenchmarkPendingSearchGate(b *testing.B) {
	j, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	segment := testSegment()
	base := segment.Events[0]
	segment.Events = nil
	for i := 0; i < 1000; i++ {
		event := base
		event.EventID = fmt.Sprintf("event-%d", i)
		event.Payload = map[string]any{"data": strings.Repeat("x", 900)}
		segment.Events = append(segment.Events, event)
	}
	if err := j.StartFreshSource(SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
		b.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		b.Fatal(err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		b.Fatal(err)
	}
	p := Processor{Journal: j, Writer: &fakeLaneWriter{}}
	b.Run("full_body", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := j.load(id); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("pending_status", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := p.DrainLane(context.Background(), id, Search); !errors.Is(err, ErrUnconfirmed) {
				b.Fatal(err)
			}
		}
	})
	if err := p.DrainLane(context.Background(), id, Archive); err != nil {
		b.Fatal(err)
	}
	verified, err := j.load(id)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ack_full_body", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := j.Ack(id, Archive); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ack_verified_status", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := j.setAckWithProof(id, Archive, Acked, verified.ContentSHA256); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func (f *fakeLaneWriter) WriteBody(context.Context, string, Segment) error {
	f.archiveWrites++
	if f.failArchiveOnce {
		f.failArchiveOnce = false
		return errors.New("response lost after commit")
	}
	return nil
}
func (f *fakeLaneWriter) ReconcileBody(context.Context, string, Segment) error {
	f.archiveChecks++
	return nil
}
func (f *fakeLaneWriter) WriteSearch(context.Context, string, Segment) error {
	f.searchWrites++
	return nil
}
func (f *fakeLaneWriter) ReconcileSearch(context.Context, string, Segment) error     { return nil }
func (f *fakeLaneWriter) Project(context.Context, string, Segment) error             { f.projects++; return nil }
func (f *fakeLaneWriter) ReconcileProjection(context.Context, string, Segment) error { return nil }

func TestProcessorKeepsIndependentProjectionAfterArchiveResponseLoss(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &fakeLaneWriter{failArchiveOnce: true}
	p := Processor{Journal: j, Writer: w}
	if err := p.Drain(context.Background(), id); err == nil {
		t.Fatal("expected ambiguous body result")
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Acks[Archive] != Attempted || state.Acks[Projection] != Acked || state.Acks[Search] != Pending {
		t.Fatalf("lanes were not independent: %+v", state.Acks)
	}
	if err := p.Drain(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if w.archiveWrites != 1 || w.archiveChecks != 1 || w.searchWrites != 1 || w.projects != 1 {
		t.Fatalf("unknown archive was resent or projection repeated: %+v", w)
	}
	if _, err := j.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fully acknowledged state was not retired: %v", err)
	}
}

func TestProcessorReleasesHeaderOnlySegmentWithoutSinkCalls(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.Events = nil
	segment.NeedsProjection = false
	id := appendCommitted(t, j, segment)
	w := &fakeLaneWriter{}
	if err := (Processor{Journal: j, Writer: w}).Drain(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if w.archiveWrites != 0 || w.searchWrites != 0 || w.projects != 0 {
		t.Fatalf("header-only input called a sink: %+v", w)
	}
}

func TestProcessorRefusesUncommittedSourceSegment(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(testSegment())
	if err != nil {
		t.Fatal(err)
	}
	w := &fakeLaneWriter{}
	if err := (Processor{Journal: j, Writer: w}).Drain(context.Background(), id); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("uncommitted source was consumed: %v", err)
	}
	if w.archiveWrites != 0 || w.projects != 0 {
		t.Fatalf("sink observed uncommitted source: %+v", w)
	}
}

type projectionRetryBudgetWriter struct {
	fakeLaneWriter
	first, retry time.Duration
}

func (w *projectionRetryBudgetWriter) Project(ctx context.Context, _ string, _ Segment) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("projection lacks deadline")
	}
	w.first = time.Until(deadline)
	return context.DeadlineExceeded
}

func (w *projectionRetryBudgetWriter) ReconcileProjection(ctx context.Context, _ string, _ Segment) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("projection retry lacks deadline")
	}
	w.retry = time.Until(deadline)
	return nil
}

func TestProjectionRetryReceivesIndependentBoundedBudget(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	original := testSegment()
	original.AcceptedAt = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	id := appendCommitted(t, j, original)
	w := &projectionRetryBudgetWriter{}
	p := Processor{Journal: j, Writer: w, SinkTimeout: 300 * time.Millisecond, ProjectionRetryTimeout: 800 * time.Millisecond}
	if err := p.DrainLane(context.Background(), id, Projection); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first attempt: %v", err)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[Projection] != Attempted || !state.Segment.AcceptedAt.Equal(original.AcceptedAt) {
		t.Fatalf("attempt was lost or time reset: %+v %v", state.Acks, err)
	}
	if err := p.DrainLane(context.Background(), id, Projection); err != nil {
		t.Fatal(err)
	}
	if w.first < 200*time.Millisecond || w.first > 300*time.Millisecond || w.retry < 700*time.Millisecond || w.retry > 800*time.Millisecond {
		t.Fatalf("unexpected budgets first=%v retry=%v", w.first, w.retry)
	}
	state, err = j.Load(id)
	if err != nil || state.Acks[Projection] != Acked || !state.Segment.AcceptedAt.Equal(original.AcceptedAt) {
		t.Fatalf("reconciled state: %+v %v", state.Acks, err)
	}
}

func TestProjectionRetryDoesNotExceedParentDeadline(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	if err := j.BeginAttempt(id, Projection); err != nil {
		t.Fatal(err)
	}
	w := &projectionRetryBudgetWriter{}
	p := Processor{Journal: j, Writer: w, SinkTimeout: 300 * time.Millisecond, ProjectionRetryTimeout: 800 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := p.DrainLane(ctx, id, Projection); err != nil {
		t.Fatal(err)
	}
	if w.retry <= 0 || w.retry > 150*time.Millisecond {
		t.Fatalf("parent deadline ignored: %v", w.retry)
	}
}

type slowProjectionRetryWriter struct{ fakeLaneWriter }

func (*slowProjectionRetryWriter) Project(ctx context.Context, _ string, _ Segment) error {
	<-ctx.Done()
	return ctx.Err()
}

func (*slowProjectionRetryWriter) ReconcileProjection(ctx context.Context, _ string, _ Segment) error {
	select {
	case <-time.After(120 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestProjectionRetryCanFinishAfterShortFirstAttempt(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.AcceptedAt = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	id := appendCommitted(t, j, segment)
	p := Processor{Journal: j, Writer: &slowProjectionRetryWriter{}, SinkTimeout: 50 * time.Millisecond, ProjectionRetryTimeout: 400 * time.Millisecond}
	if err = p.DrainLane(context.Background(), id, Projection); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout: %v", err)
	}
	if err = p.DrainLane(context.Background(), id, Projection); err != nil {
		t.Fatalf("retry did not finish: %v", err)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[Projection] != Acked || !state.Segment.AcceptedAt.Equal(segment.AcceptedAt) {
		t.Fatalf("retry lost state: %+v %v", state.Acks, err)
	}
}
