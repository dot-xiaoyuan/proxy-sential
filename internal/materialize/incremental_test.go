package materialize

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

type incrementalFake struct {
	claims         []store.RiskSubjectClaim
	events         []normalized.Event
	readErr        error
	applied        int
	released       int
	saved          []risk.Snapshot
	facts          []evidence.Evidence
	claimed        []store.RiskSubjectClaim
	claimLimit     int
	claimDelay     time.Duration
	cutoff         time.Time
	readCutoff     time.Time
	expiryCalls    int
	streamN        int
	streamCalls    int
	failCall       int
	boundGroupSize int
	failBoundID    string
	appliedGroups  [][]store.RiskSubjectClaim
	releasedClaims []store.RiskSubjectClaim
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

func (f *incrementalFake) ClaimRiskSubjects(_ context.Context, _ string, limit int) ([]store.RiskSubjectClaim, error) {
	f.claimLimit = limit
	time.Sleep(f.claimDelay)
	return f.claims[:min(limit, len(f.claims))], nil
}

func TestIncrementalRiskPreservesClaimElapsed(t *testing.T) {
	now := time.Now().UTC()
	delay := 2 * time.Millisecond
	backend := &incrementalFake{
		cutoff:     now.Add(-time.Minute),
		claimDelay: delay,
		claims:     []store.RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.1"}},
	}
	result, err := RunIncrementalOnce(context.Background(), backend, IncrementalOptions{
		SensorID: "sensor-a", AsOf: now, SkipExpiry: true,
	})
	if err != nil || result.Committed != 1 || result.ClaimElapsed < delay {
		t.Fatalf("claim timing was lost: committed=%d elapsed=%s err=%v", result.Committed, result.ClaimElapsed, err)
	}
}

func (f *incrementalFake) StreamRiskFeatureEvents(_ context.Context, _ string, claims []store.RiskSubjectClaim, _, _, acceptedAfter time.Time, _ int, emit func(normalized.Event) error) (int, error) {
	f.claimed = claims
	f.readCutoff = acceptedAfter
	f.streamCalls++
	if f.boundGroupSize > 0 && len(claims) > f.boundGroupSize {
		return 0, store.ErrRiskFeatureStreamBound
	}
	if len(claims) == 1 && claims[0].ID == f.failBoundID {
		return 0, store.ErrRiskFeatureStreamBound
	}
	if f.readErr != nil || f.failCall == f.streamCalls {
		if f.readErr != nil {
			return 0, f.readErr
		}
		return 0, errors.New("later risk page unavailable")
	}
	count := 0
	for _, event := range f.events {
		if err := emit(event); err != nil {
			return count, err
		}
		count++
	}
	for index := 0; index < f.streamN; index++ {
		claim := claims[0]
		event := normalized.Event{EventID: "bulk-" + strconv.Itoa(index), Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Type: "flow", Subject: map[string]any{"ip": claim.ID}}
		if err := emit(event); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
func (f *incrementalFake) ApplyStreamRiskEvaluation(_ context.Context, _ string, claims []store.RiskSubjectClaim, facts []evidence.Evidence, snapshots []risk.Snapshot, _ time.Time) (int, error) {
	f.applied++
	f.appliedGroups = append(f.appliedGroups, append([]store.RiskSubjectClaim(nil), claims...))
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
func (f *incrementalFake) ReleaseRiskSubjects(_ context.Context, claims []store.RiskSubjectClaim) error {
	f.released++
	f.releasedClaims = append(f.releasedClaims, claims...)
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

func TestIncrementalRiskProcessesSingleSubjectBeyondOldDistinctLimit(t *testing.T) {
	now := time.Now().UTC()
	claim := store.RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 4}
	f := &incrementalFake{claims: []store.RiskSubjectClaim{claim}, cutoff: now.Add(-time.Hour), streamN: 20001}
	result, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: now, Window: 30 * time.Minute, SkipExpiry: true})
	if err != nil || result.FullBatch || result.Features != 20001 || result.Committed != 1 || f.applied != 1 || f.released != 0 {
		t.Fatalf("hot subject was truncated or not committed: result=%+v applied=%d released=%d err=%v", result, f.applied, f.released, err)
	}
}

func TestIncrementalRiskReleasesOnlyUncommittedGroupAfterReadFailure(t *testing.T) {
	now := time.Now().UTC()
	claims := make([]store.RiskSubjectClaim, 8)
	for index := range claims {
		claims[index] = store.RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2." + strconv.Itoa(index+1), Generation: int64(index + 1)}
	}
	f := &incrementalFake{claims: claims, cutoff: now.Add(-time.Hour), boundGroupSize: 4, failCall: 3}
	result, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: now, Window: 30 * time.Minute, SkipExpiry: true})
	if err == nil || result.Committed != 4 || len(f.appliedGroups) != 1 || len(f.appliedGroups[0]) != 4 || len(f.releasedClaims) != 4 || f.releasedClaims[0].ID != claims[4].ID {
		t.Fatalf("partial failure released acknowledged subjects or lost a pending claim: result=%+v applied=%v released=%v err=%v", result, f.appliedGroups, f.releasedClaims, err)
	}
}

func TestIncrementalRiskSplitsOversizedGroupWithoutSkippingClaims(t *testing.T) {
	now := time.Now().UTC()
	claims := make([]store.RiskSubjectClaim, 8)
	for index := range claims {
		claims[index] = store.RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2." + strconv.Itoa(index+1), Generation: int64(index + 1)}
	}
	f := &incrementalFake{claims: claims, cutoff: now.Add(-time.Hour), boundGroupSize: 2}
	result, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: now, Window: 30 * time.Minute, SkipExpiry: true})
	if err != nil || !result.FullBatch || result.Committed != 8 || f.applied != 4 || f.released != 0 {
		t.Fatalf("group split lost risk claims: result=%+v groups=%v released=%v err=%v", result, f.appliedGroups, f.releasedClaims, err)
	}
	if f.claimLimit != 8 {
		t.Fatalf("risk worker leased %d claims despite an eight-subject bound", f.claimLimit)
	}
}

func TestIncrementalRiskCombinesFullDrainBatchInOneCommit(t *testing.T) {
	now := time.Now().UTC()
	claims := make([]store.RiskSubjectClaim, 30)
	for index := range claims {
		claims[index] = store.RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2." + strconv.Itoa(index+1), Generation: int64(index + 1)}
	}
	f := &incrementalFake{claims: claims, cutoff: now.Add(-time.Hour)}
	result, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: now, SkipExpiry: true, Drain: true})
	if err != nil || !result.FullBatch || result.Claims != 24 || result.Committed != 24 || f.streamCalls != 1 || len(f.appliedGroups) != 1 || len(f.appliedGroups[0]) != 24 || f.released != 0 {
		t.Fatalf("drain batch did not combine claim and write: result=%+v reads=%d groups=%v err=%v", result, f.streamCalls, f.appliedGroups, err)
	}
}

func TestIncrementalRiskHotSingletonStaysPendingWhileOtherClaimsCommit(t *testing.T) {
	now := time.Now().UTC()
	claims := []store.RiskSubjectClaim{
		{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.1", Generation: 1},
		{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.2", Generation: 2},
	}
	f := &incrementalFake{claims: claims, cutoff: now.Add(-time.Hour), boundGroupSize: 1}
	f.readErr = nil
	// The first singleton hits a deterministic capacity guard; the second can
	// still be evaluated and committed in the same claimed batch.
	f.failBoundID = claims[0].ID
	result, err := RunIncrementalOnce(context.Background(), f, IncrementalOptions{SensorID: "sensor-a", AsOf: now, Window: 30 * time.Minute, SkipExpiry: true})
	if !errors.Is(err, store.ErrRiskFeatureStreamBound) || result.Committed != 1 || len(f.releasedClaims) != 0 {
		t.Fatalf("hot singleton lost its retry lease or blocked other subjects: result=%+v released=%v err=%v", result, f.releasedClaims, err)
	}
}
