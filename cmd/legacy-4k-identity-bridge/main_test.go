package main

import (
	"errors"
	"testing"
	"time"
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
