package materialize

import (
	"context"
	"errors"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

type dedicatedRouterReplay struct {
	ownerError   error
	routerWrites int
}

func (r *dedicatedRouterReplay) ListEventSamples(context.Context, store.Query) ([]normalized.Event, error) {
	return nil, nil
}
func (r *dedicatedRouterReplay) WriteEvidence(context.Context, []evidence.Evidence) error { return nil }
func (r *dedicatedRouterReplay) WriteRiskSnapshots(context.Context, []risk.Snapshot) error {
	return nil
}
func (r *dedicatedRouterReplay) ExpireRiskSnapshots(context.Context, time.Time) error { return nil }
func (r *dedicatedRouterReplay) WriteCollectorRun(context.Context, store.Run) error   { return nil }
func (r *dedicatedRouterReplay) WriteRouterObservations(context.Context, evidence.RouterResult) error {
	r.routerWrites++
	return nil
}
func (r *dedicatedRouterReplay) DedicatedRouterObservationsHealthy(context.Context, string, time.Time) error {
	return r.ownerError
}

func TestDedicatedRouterOwnerAvoidsDuplicateFullWindowPersistence(t *testing.T) {
	replay := &dedicatedRouterReplay{}
	if _, err := RunOnce(context.Background(), replay, Options{RouterDedicated: true, SensorID: "same-sensor", Window: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if replay.routerWrites != 0 {
		t.Fatal("rolling risk job still repeated the dedicated router projection")
	}
}

func TestDedicatedRouterOwnerFailureDoesNotFallBackToDuplicateWrite(t *testing.T) {
	replay := &dedicatedRouterReplay{ownerError: errors.New("cursor stale")}
	if _, err := RunOnce(context.Background(), replay, Options{RouterDedicated: true, SensorID: "same-sensor", Window: 10 * time.Minute}); err == nil {
		t.Fatal("unhealthy dedicated owner was silently ignored")
	}
	if replay.routerWrites != 0 {
		t.Fatal("unhealthy owner caused a duplicate full-window router write")
	}
}
