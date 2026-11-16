package main

import (
	"testing"

	"proxy-sentinel/internal/streamlog"
)

func TestConfirmedRawRequiresSettledArchiveLane(t *testing.T) {
	for _, item := range []struct {
		lane    streamlog.Lane
		settled bool
	}{
		{streamlog.Archive, false}, {streamlog.Search, true}, {"risk-feature", true},
	} {
		if err := runWithConfirmedRaw("journal", "segment", item.lane, item.settled, true); err == nil {
			t.Fatalf("confirmed raw accepted outside settled archive: %+v", item)
		}
	}
}

func TestSettledPacketRiskRepairUsesFeatureLaneInsteadOfSearchAck(t *testing.T) {
	state := streamlog.State{Committed: true, Segment: streamlog.Segment{RiskFeaturesRequired: true, SplitRiskFeatures: true},
		Acks: map[streamlog.Lane]streamlog.Status{
			streamlog.Archive: streamlog.Acked, streamlog.Search: streamlog.Acked,
			streamlog.RiskFeatures: streamlog.Attempted,
		}}
	if err := validateRepairCandidate(state, "risk-feature", true); err != nil {
		t.Fatalf("split attempted risk feature with confirmed body and search rejected: %v", err)
	}
	state.Acks[streamlog.RiskFeatures] = streamlog.Pending
	if err := validateRepairCandidate(state, "risk-feature", true); err == nil {
		t.Fatal("unattempted risk feature accepted")
	}
	state.Acks[streamlog.RiskFeatures] = streamlog.Attempted
	state.Acks[streamlog.Search] = streamlog.Attempted
	if err := validateRepairCandidate(state, "risk-feature", true); err == nil {
		t.Fatal("unconfirmed search accepted")
	}
	state.Acks[streamlog.Search] = streamlog.Acked
	state.Acks[streamlog.Archive] = streamlog.Pending
	if err := validateRepairCandidate(state, "risk-feature", true); err == nil {
		t.Fatal("unconfirmed authoritative body accepted")
	}
}

func TestCoupledRiskFeatureKeepsShortWindowSearchLane(t *testing.T) {
	state := streamlog.State{Committed: true, Segment: streamlog.Segment{RiskFeaturesRequired: true},
		Acks: map[streamlog.Lane]streamlog.Status{
			streamlog.Archive: streamlog.Acked, streamlog.Search: streamlog.Attempted,
		}}
	if err := validateRepairCandidate(state, "risk-feature", false); err != nil {
		t.Fatalf("coupled risk feature short repair rejected: %v", err)
	}
	if err := validateRepairCandidate(state, "risk-feature", true); err == nil {
		t.Fatal("coupled risk feature accepted for settled split repair")
	}
}
