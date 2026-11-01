package store

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"proxy-sentinel/internal/streamlog"
)

type witnessProjector struct {
	calls      []string
	witnessErr error
}

func (*witnessProjector) ProjectStreamSegment(context.Context, string, streamlog.Segment) error {
	return nil
}

func (*witnessProjector) ReconcileStreamProjection(context.Context, string, streamlog.Segment) error {
	return nil
}

func (p *witnessProjector) MarkStreamArchiveConfirmed(context.Context, string, streamlog.Segment) error {
	p.calls = append(p.calls, "archive")
	return nil
}

func (p *witnessProjector) MarkStreamSegmentFinalized(context.Context, string, streamlog.Segment) error {
	p.calls = append(p.calls, "witness")
	return p.witnessErr
}

type witnessSharedQueue struct{ calls *[]string }

func (q witnessSharedQueue) MarkStreamSharedJobs(context.Context, string, streamlog.Segment) error {
	*q.calls = append(*q.calls, "shared")
	return nil
}

type archiveOnlyProjector struct{}

func (archiveOnlyProjector) ProjectStreamSegment(context.Context, string, streamlog.Segment) error {
	return nil
}

func (archiveOnlyProjector) ReconcileStreamProjection(context.Context, string, streamlog.Segment) error {
	return nil
}

func (archiveOnlyProjector) MarkStreamArchiveConfirmed(context.Context, string, streamlog.Segment) error {
	return nil
}

func TestProjectedSegmentRequiresFinalizationWitness(t *testing.T) {
	segment := testStreamSegment()
	if err := (StreamLaneWriter{Projector: archiveOnlyProjector{}}).FinalizeSegment(context.Background(), "segment-a", segment); !errors.Is(err, ErrStreamProjectorUnavailable) {
		t.Fatalf("projected segment released without witness: %v", err)
	}
	segment.NeedsProjection = false
	if err := (StreamLaneWriter{Projector: archiveOnlyProjector{}}).FinalizeSegment(context.Background(), "segment-a", segment); err != nil {
		t.Fatalf("unprojected segment was blocked by witness: %v", err)
	}
}

func TestStreamFinalizationWitnessFollowsOtherReceipts(t *testing.T) {
	projector := &witnessProjector{}
	segment := testStreamSegment()
	segment.Events[0].Source = "handshake-sidecar"
	segment.Events[0].SourceEventType = "handshake"
	writer := StreamLaneWriter{Projector: projector, SharedQueue: witnessSharedQueue{calls: &projector.calls}}
	if err := writer.FinalizeSegment(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projector.calls, []string{"archive", "shared", "witness"}) {
		t.Fatalf("witness preceded a required receipt: %v", projector.calls)
	}
	projector.calls = nil
	segment.SplitRiskFeatures, segment.RiskFeaturesRequired = true, true
	if err := writer.FinalizeSegment(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projector.calls, []string{"archive", "shared", "witness"}) {
		t.Fatalf("split feature path skipped witness: %v", projector.calls)
	}
}

func TestStreamWitnessFailureKeepsJournalForRetry(t *testing.T) {
	segment := testStreamSegment()
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	for _, lane := range []streamlog.Lane{streamlog.Archive, streamlog.Search, streamlog.Projection} {
		if err := j.Ack(id, lane); err != nil {
			t.Fatal(err)
		}
	}
	projector := &witnessProjector{witnessErr: errors.New("unknown database outcome")}
	processor := streamlog.Processor{Journal: j, Writer: StreamLaneWriter{Projector: projector}}
	if err := processor.FinalizeAfterLanes(context.Background(), id); err == nil {
		t.Fatal("ambiguous witness released its journal segment")
	}
	if _, err := j.Load(id); err != nil {
		t.Fatalf("failed witness lost segment: %v", err)
	}
	projector.witnessErr = nil
	if err := processor.FinalizeAfterLanes(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful retry left segment: %v", err)
	}
	if !reflect.DeepEqual(projector.calls, []string{"archive", "witness", "archive", "witness"}) {
		t.Fatalf("finalization retry order changed: %v", projector.calls)
	}
}
