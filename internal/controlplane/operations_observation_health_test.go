package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestObservationWorkerHealthClearsOnlyAfterItsOwnRetry(t *testing.T) {
	state := &operationsState{}
	state.setQueuedNotificationHealthError(errors.New("notification insert timed out"))
	state.setQueuedBehaviorReportHealthError(errors.New("report insert timed out"))
	if err := state.health(context.Background()); err == nil || !strings.Contains(err.Error(), "notification insert timed out") {
		t.Fatalf("notification failure was hidden: %v", err)
	}
	state.setQueuedNotificationHealthError(nil)
	if err := state.health(context.Background()); err == nil || !strings.Contains(err.Error(), "report insert timed out") {
		t.Fatalf("unrelated worker success hid report failure: %v", err)
	}
	state.setQueuedBehaviorReportHealthError(nil)
	if err := state.health(context.Background()); err != nil {
		t.Fatalf("successful retries left a stale worker failure: %v", err)
	}
}
