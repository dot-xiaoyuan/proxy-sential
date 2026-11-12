package streamlog

import (
	"context"
	"sync"
	"testing"
	"time"
)

type processorObservation struct {
	lane   Lane
	stage  ProcessorStage
	failed bool
}
type processorObservations struct {
	mu    sync.Mutex
	items []processorObservation
}

func (o *processorObservations) observe(lane Lane, stage ProcessorStage, elapsed time.Duration, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.items = append(o.items, processorObservation{lane, stage, err != nil})
}
func (o *processorObservations) count(lane Lane, stage ProcessorStage, failed bool) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, item := range o.items {
		if item == (processorObservation{lane, stage, failed}) {
			n++
		}
	}
	return n
}

func TestProcessorObserverSeparatesJournalAndSinkRecovery(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &finalizingWriter{fakeLaneWriter: fakeLaneWriter{failArchiveOnce: true}, failOnce: true}
	var observed processorObservations
	p := Processor{Journal: j, Writer: w, Observer: observed.observe}
	if err := p.DrainLane(context.Background(), id, Archive); err == nil {
		t.Fatal("expected archive response loss")
	}
	if observed.count(Archive, StageWrite, true) != 1 || observed.count(Archive, StageAck, false) != 0 {
		t.Fatal("failed sink write reported as journal ack")
	}
	// Recovery uses the durable attempted marker, and must be measured separately.
	reopened, err := Open(j.Directory())
	if err != nil {
		t.Fatal(err)
	}
	p.Journal = reopened
	for _, lane := range []Lane{Archive, Search, Projection} {
		if err := p.DrainLane(context.Background(), id, lane); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); err == nil {
		t.Fatal("expected finalization failure")
	}
	if observed.count("", StageFinalize, true) != 1 || observed.count("", StageRelease, false) != 0 {
		t.Fatal("failed confirmation released journal")
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	for _, want := range []processorObservation{{Archive, StageLoad, false}, {Archive, StageBeginAttempt, false}, {Archive, StageReconcile, false}, {Archive, StageAck, false}, {"", StageFinalize, false}, {"", StageRelease, false}} {
		if observed.count(want.lane, want.stage, want.failed) == 0 {
			t.Errorf("missing observation: %+v", want)
		}
	}
}

func TestProcessorObserverRecordsLocalFailuresWithoutSinkCalls(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &rejectingPreflightWriter{}
	var observed processorObservations
	p := Processor{Journal: j, Writer: w, Observer: observed.observe}
	if err := p.DrainLane(context.Background(), id, Archive); err == nil {
		t.Fatal("expected local rejection")
	}
	if observed.count(Archive, StagePreflight, true) != 1 || observed.count(Archive, StageWrite, false) != 0 {
		t.Fatal("preflight reported as sink work")
	}
	if err := p.DrainLane(context.Background(), "missing", Projection); err == nil {
		t.Fatal("expected load failure")
	}
	if observed.count(Projection, StageLoad, true) != 1 {
		t.Fatal("load failure missing")
	}
}

func TestProcessorAckObserverCountsOnlyDurableTransitions(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	w := &fakeLaneWriter{failArchiveOnce: true}
	var confirmed []Lane
	p := Processor{Journal: j, Writer: w, AckObserver: func(lane Lane, segment Segment) {
		if len(segment.Events) == 0 {
			t.Fatal("ack observer lost the confirmed segment")
		}
		confirmed = append(confirmed, lane)
	}}
	if err := p.DrainLane(context.Background(), id, Archive); err == nil {
		t.Fatal("expected first archive failure")
	}
	if len(confirmed) != 0 {
		t.Fatalf("failed write was counted as confirmed: %v", confirmed)
	}
	if err := p.DrainLane(context.Background(), id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := p.DrainLane(context.Background(), id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := p.DrainLane(context.Background(), id, Search); err != nil {
		t.Fatal(err)
	}
	if len(confirmed) != 2 || confirmed[0] != Archive || confirmed[1] != Search {
		t.Fatalf("lane confirmation counted twice or missed: %v", confirmed)
	}
}
