package main

import (
	"errors"
	"testing"
	"time"

	"proxy-sentinel/internal/legacy4k"
)

func TestRealtimeRecoveryDoesNotHideSnapshotFailure(t *testing.T) {
	state := &runtimeState{snapshotState: "healthy", eventChannelState: "healthy", overallState: "healthy", lastSnapshotAt: time.Now().UTC()}
	markSnapshotFailure(state, errors.New("snapshot failed"))
	markEventHealthy(state)
	if state.snapshotConsecutiveFailures != 1 || state.snapshotState != "failed" || state.overallState != "degraded" {
		t.Fatalf("realtime success hid snapshot failure: %+v", state)
	}
}

func TestSnapshotRecoveryDoesNotHideRealtimeFailure(t *testing.T) {
	state := &runtimeState{eventChannelState: "healthy", snapshotState: "healthy", overallState: "healthy"}
	markEventFailure(state, errors.New("event failed"))
	markSnapshotSuccess(state, "192.0.2.1:16380", 2, snapshotResult{observedAt: time.Now().UTC(), instanceID: "epoch", members: 2, records: 2})
	if state.eventConsecutiveFailures != 1 || state.eventChannelState != "failed" || state.overallState != "degraded" {
		t.Fatalf("snapshot success hid realtime failure: %+v", state)
	}
}

func TestSnapshotFreshnessHasIndependentHealthBoundary(t *testing.T) {
	state := &runtimeState{lastSnapshotAt: time.Now().Add(-91 * time.Minute), snapshotState: "healthy", eventChannelState: "healthy", overallState: "healthy"}
	if got := deriveOverallState(state, 30*time.Minute); got != "degraded" {
		t.Fatalf("stale snapshot state=%s", got)
	}
	state.lastSnapshotAt = time.Now()
	state.snapshotConsecutiveFailures = 5
	if got := deriveOverallState(state, 30*time.Minute); got != "degraded" {
		t.Fatalf("snapshot failure counter state=%s", got)
	}
}

func TestQuarantineRecordsMissingUsableAddress(t *testing.T) {
	raw := `{"action":1,"session_id":"session","user_name":"account","ip":"0.0.0.0","ip6":"::"}`
	records, err := legacy4k.DecodeRecordsForInstance(raw, "source", time.Now())
	if len(records) != 0 || errorType(err) != "no_usable_identity_address" {
		t.Fatalf("records=%v error=%v category=%s", records, err, errorType(err))
	}
}
