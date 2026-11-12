package streamlog

import (
	"context"
	"errors"
	"testing"
)

type retryEventBusWriter struct {
	fakeLaneWriter
	fail   bool
	writes int
}

func (w *retryEventBusWriter) WriteEventBus(context.Context, string, Segment) error {
	w.writes++
	if w.fail {
		return errors.New("broker acknowledgement missing")
	}
	return nil
}

func (w *retryEventBusWriter) ReconcileEventBus(ctx context.Context, id string, segment Segment) error {
	return w.WriteEventBus(ctx, id, segment)
}

func TestEventBusLaneRetainsSegmentAcrossBrokerFailureAndRestart(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.EventBusRequired = true
	id := appendCommitted(t, j, segment)
	writer := &retryEventBusWriter{fail: true}
	p := Processor{Journal: j, Writer: writer}
	for _, lane := range []Lane{Archive, Search, Projection} {
		if err := p.DrainLane(context.Background(), id, lane); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.DrainLane(context.Background(), id, EventBus); err == nil {
		t.Fatal("expected broker failure")
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("released without broker ACK: %v", err)
	}
	j, err = Open(j.Directory())
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[EventBus] != Attempted || !state.Segment.EventBusRequired {
		t.Fatalf("lost pending broker delivery: %+v %v", state, err)
	}
	lanes, err := j.PendingLanes(id)
	if err != nil || len(lanes) != 1 || lanes[0] != EventBus {
		t.Fatalf("recovery lanes=%v err=%v", lanes, err)
	}
	writer.fail = false
	p.Journal = j
	if err := p.DrainLane(context.Background(), id, EventBus); err != nil {
		current, loadErr := j.Load(id)
		t.Fatalf("retry failed: %v, current=%+v required=%v load=%v writes=%d", err, current.Acks, current.Segment.EventBusRequired, loadErr, writer.writes)
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if writer.writes != 2 {
		t.Fatalf("expected one retry after restart, got %d", writer.writes)
	}
}

func TestEventBusLaneCannotBeAddedToOldSegment(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	if err := j.BeginAttempt(id, EventBus); err == nil {
		t.Fatal("old segment gained a new required sink")
	}
}
