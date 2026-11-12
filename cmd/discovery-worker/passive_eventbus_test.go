package main

import (
	"context"
	"testing"

	"proxy-sentinel/internal/streamlog"
)

type recordingPassiveJournal struct{ segment streamlog.Segment }

func (*recordingPassiveJournal) LoadSource(string, string) (streamlog.SourceCursor, error) {
	return streamlog.SourceCursor{}, nil
}

func (j *recordingPassiveJournal) AppendAndCommitPassive(segment streamlog.Segment) (string, error) {
	j.segment = segment
	return "segment", nil
}

func TestReliableCanaryPersistsDecisionBeforeAppend(t *testing.T) {
	underlying := &recordingPassiveJournal{}
	journal := passiveReliableCaptureJournal{PassiveStreamJournal: underlying}
	original := streamlog.Segment{Source: "passive-discovery"}
	if _, err := journal.AppendAndCommitPassive(original); err != nil {
		t.Fatal(err)
	}
	if !underlying.segment.EventBusRequired || original.EventBusRequired {
		t.Fatalf("canary decision did not persist at append boundary: underlying=%v original=%v", underlying.segment.EventBusRequired, original.EventBusRequired)
	}
	if err := (passiveEventBusLaneWriter{}).WriteEventBus(context.Background(), "segment", original); err == nil {
		t.Fatal("missing producer silently acknowledged segment")
	}
}
