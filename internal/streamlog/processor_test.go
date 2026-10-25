package streamlog

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type fakeLaneWriter struct {
	archiveWrites   int
	archiveChecks   int
	searchWrites    int
	projects        int
	failArchiveOnce bool
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
}

func (w *finalizingWriter) FinalizeSegment(context.Context, string, Segment) error {
	w.finalizations++
	if w.failOnce {
		w.failOnce = false
		return errors.New("confirmation state unavailable")
	}
	return nil
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
