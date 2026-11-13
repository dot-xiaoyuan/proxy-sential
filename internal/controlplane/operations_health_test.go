package controlplane

import (
	"context"
	"errors"
	"testing"
)

func TestDueActionHealthRecoversWithoutHidingOtherFailures(t *testing.T) {
	state := &operationsState{}
	dueFailure := errors.New("due action query timed out")
	transactionFailure := errors.New("operation commit failed")
	state.setDueActionHealthError(dueFailure)
	if err := state.health(context.Background()); !errors.Is(err, dueFailure) {
		t.Fatalf("due action failure was not reported: %v", err)
	}
	state.setHealthError(transactionFailure)
	state.setDueActionHealthError(nil)
	if err := state.health(context.Background()); !errors.Is(err, transactionFailure) {
		t.Fatalf("due action recovery hid an unrelated transaction failure: %v", err)
	}
	state.setHealthError(nil)
	if err := state.health(context.Background()); err != nil {
		t.Fatalf("recovered operations stayed unhealthy: %v", err)
	}
}

func TestObservationHealthRecoversWithoutHidingDueActionFailure(t *testing.T) {
	state := &operationsState{}
	observationFailure := errors.New("observation insert timed out")
	dueFailure := errors.New("due action scan failed")
	state.setOutboundObservationHealthError(observationFailure)
	if err := state.health(context.Background()); !errors.Is(err, observationFailure) {
		t.Fatalf("outbound observation failure was not reported: %v", err)
	}
	state.setDueActionHealthError(dueFailure)
	state.setOutboundObservationHealthError(nil)
	if err := state.health(context.Background()); !errors.Is(err, dueFailure) {
		t.Fatalf("observation recovery hid due action failure: %v", err)
	}
	state.setDueActionHealthError(nil)
	if err := state.health(context.Background()); err != nil {
		t.Fatalf("recovered operations stayed unhealthy: %v", err)
	}
}
