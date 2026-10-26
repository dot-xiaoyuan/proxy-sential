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

type incrementalFake struct {
	claims      []store.RiskSubjectClaim
	events      []normalized.Event
	readErr     error
	applied     int
	released    int
	saved       []risk.Snapshot
	facts       []evidence.Evidence
	claimed     []store.RiskSubjectClaim
	cutoff      time.Time
	readCutoff  time.Time
	expiryCalls int
}

func (f *incrementalFake) StreamRiskFreshCutoff(_ context.Context, _ string) (time.Time, error) {
	return f.cutoff, nil
}

func (f *incrementalFake) QueueExpiredStreamRiskSubjects(_ context.Context, _ string, _ time.Time, _ int) error {
	f.expiryCalls++
	return nil
}

func TestIncrementalRiskCanKeepExpiryOutOfRealtimeBatch(t *testing.T) {
	now := time.Now().UTC()
	f := &incrementalFake{cutoff: now.Add(-time.Minute)}
	if _, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: now, SkipExpiry: true}); err != nil || f.expiryCalls != 0 {
		t.Fatalf("realtime batch ran expiry scan: calls=%d err=%v", f.expiryCalls, err)
	}
}

func (f *incrementalFake) ClaimRiskSubjects(_ context.Context, _ string, _ int) ([]store.RiskSubjectClaim, error) {
	return f.claims, nil
}
func (f *incrementalFake) ListStreamRiskFeatureEvents(_ context.Context, _ string, claims []store.RiskSubjectClaim, _, _, acceptedAfter time.Time, _ int) ([]normalized.Event, error) {
	f.claimed = claims
	f.readCutoff = acceptedAfter
	return f.events, f.readErr
}
func (f *incrementalFake) ApplyStreamRiskEvaluation(_ context.Context, _ string, claims []store.RiskSubjectClaim, facts []evidence.Evidence, snapshots []risk.Snapshot, _ time.Time) (int, error) {
	f.applied++
	f.facts = facts
	f.saved = snapshots
	return len(claims), nil
}

func TestIncrementalRiskKeepsStableEvidenceKeyAcrossRepeatedObservation(t *testing.T) {
	now := time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC)
	claim := store.RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 4}
	makeEvents := func(latest time.Time) []normalized.Event {
		return []normalized.Event{
			{EventID: "a", Timestamp: latest.Add(-time.Second).Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": claim.ID}, Payload: map[string]any{"origin": "ttl", "ttl": 63}, Flow: map[string]any{"direction": "outbound"}},
			{EventID: "b", Timestamp: latest.Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": claim.ID}, Payload: map[string]any{"origin": "ttl", "ttl": 126}, Flow: map[string]any{"direction": "outbound"}},
		}
	}
	first := &incrementalFake{claims: []store.RiskSubjectClaim{claim}, events: makeEvents(now.Add(-time.Minute)), cutoff: now.Add(-5 * time.Minute)}
	second := &incrementalFake{claims: []store.RiskSubjectClaim{claim}, events: makeEvents(now), cutoff: now.Add(-5 * time.Minute)}
	for _, backend := range []*incrementalFake{first, second} {
		if _, err := RunIncrementalOnce(context.Background(), backend, IncrementalOptions{SensorID: "sensor-a", AsOf: now, Window: 10 * time.Minute}); err != nil {
			t.Fatal(err)
		}
	}
	if len(first.facts) == 0 || len(first.saved) == 0 || len(second.facts) == 0 || first.facts[0].EvidenceID != second.facts[0].EvidenceID {
		t.Fatalf("repeated rule interpretation created another evidence key: first=%+v second=%+v", first.facts, second.facts)
	}
	if !first.readCutoff.Equal(first.cutoff) || !second.readCutoff.Equal(second.cutoff) {
		t.Fatal("incremental risk read did not enforce the audited fresh cutoff")
	}
}
func (f *incrementalFake) ReleaseRiskSubjects(_ context.Context, _ []store.RiskSubjectClaim) error {
	f.released++
	return nil
}

func TestIncrementalRiskExpiresClaimWithNoFeature(t *testing.T) {
	now := time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC)
	f := &incrementalFake{claims: []store.RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 4}}, cutoff: now.Add(-5 * time.Minute)}
	result, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: now, Window: 10 * time.Minute})
	if err != nil || result.Claims != 1 || f.applied != 1 || len(f.saved) != 0 || f.released != 0 {
		t.Fatalf("empty feature claim must be committed as expiry: %+v %+v %v", result, f, err)
	}
}

func TestIncrementalRiskReadFailureReleasesClaim(t *testing.T) {
	f := &incrementalFake{claims: []store.RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 4}}, readErr: errors.New("clickhouse unavailable"), cutoff: time.Now().UTC().Add(-5 * time.Minute)}
	_, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: time.Now().UTC(), Window: 10 * time.Minute})
	if err == nil || f.applied != 0 || f.released != 1 {
		t.Fatalf("failed read must not acknowledge claim: applied=%d released=%d err=%v", f.applied, f.released, err)
	}
}

func TestIncrementalRiskRefusesMissingFreshCutoff(t *testing.T) {
	f := &incrementalFake{}
	if _, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: time.Now().UTC()}); err == nil {
		t.Fatal("risk materializer silently processed old dirty subjects")
	}
}
