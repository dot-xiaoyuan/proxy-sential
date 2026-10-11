package controlplane

import (
	"context"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/poison"
	"proxy-sentinel/internal/store"
)

// destinationTargetFakeStore captures what the worker persists without needing
// ClickHouse or PostgreSQL, so the derivation rules can be asserted directly.
type destinationTargetFakeStore struct {
	// store.Reader is embedded only to satisfy the server field type; every
	// method the worker calls is overridden below.
	store.Reader
	rules        []store.DestinationTargetRule
	observations []poison.Observation
	written      []store.DestinationTargetFinding
	evidence     []evidence.Evidence
	expired      int
}

func (f *destinationTargetFakeStore) ListDestinationTargetRules(context.Context) ([]store.DestinationTargetRule, error) {
	return f.rules, nil
}

func (f *destinationTargetFakeStore) WriteDestinationTargetFindings(_ context.Context, findings []store.DestinationTargetFinding) error {
	f.written = append(f.written, findings...)
	return nil
}

func (f *destinationTargetFakeStore) ExpireDestinationTargetFindings(context.Context, time.Time) error {
	f.expired++
	return nil
}

func (f *destinationTargetFakeStore) ListDestinationObservations(context.Context, time.Time, int) ([]poison.Observation, error) {
	return f.observations, nil
}

func (f *destinationTargetFakeStore) WriteEvidence(_ context.Context, items []evidence.Evidence) error {
	f.evidence = append(f.evidence, items...)
	return nil
}

func TestDestinationTargetWorkerDerivesWeakEvidence(t *testing.T) {
	now := time.Now().UTC()
	fake := &destinationTargetFakeStore{
		rules: []store.DestinationTargetRule{{
			RuleID: "ncu-sensitive-range", Name: "敏感网段访问", Enabled: true,
			BehaviorType: poison.BehaviorConfiguredRange, TargetType: "cidr",
			Targets: []string{"10.155.32.0/24"}, WindowSeconds: 3600, Threshold: 2, Direction: "any",
		}},
		observations: []poison.Observation{
			{SubjectIP: "10.155.9.9", DstIP: "10.155.32.11", Direction: "outbound", At: now.Add(-2 * time.Minute), Count: 3},
			{SubjectIP: "10.155.9.9", DstIP: "10.155.32.12", Direction: "outbound", At: now.Add(-time.Minute), Count: 1},
		},
	}
	server := &Server{reader: fake}
	server.processDestinationTargets(now)

	if len(fake.written) != 1 {
		t.Fatalf("expected one finding, got %+v", fake.written)
	}
	finding := fake.written[0]
	if finding.SubjectIP != "10.155.9.9" || finding.HitCount != 4 || finding.UniqueDestinations != 2 {
		t.Fatalf("unexpected finding: %+v", finding)
	}
	if finding.FindingID == "" || finding.WindowStart == "" || finding.WindowEnd == "" {
		t.Fatalf("finding must carry a stable id and window: %+v", finding)
	}
	if len(fake.evidence) != 1 {
		t.Fatalf("expected one evidence item, got %+v", fake.evidence)
	}
	item := fake.evidence[0]
	if item.Type != "internal_target_access" {
		t.Fatalf("unexpected evidence type: %+v", item)
	}
	if item.Score <= 0 || item.Score > 30 {
		t.Fatalf("internal target access must remain a capped weak signal: %+v", item)
	}
	if item.Severity == "critical" || item.Severity == "high" {
		t.Fatalf("weak clue must not claim high severity: %+v", item)
	}
	if item.Reason == "" || len(item.Samples) == 0 || item.Window == "" {
		t.Fatalf("evidence must be explainable: %+v", item)
	}
	if fake.expired != 1 {
		t.Fatalf("findings must be expired on every pass, got %d", fake.expired)
	}
}

func TestDestinationTargetWorkerDoesNothingWhenNoRuleIsEnabled(t *testing.T) {
	now := time.Now().UTC()
	fake := &destinationTargetFakeStore{
		rules: []store.DestinationTargetRule{{RuleID: "off", Name: "未启用", Enabled: false, BehaviorType: poison.BehaviorHighFrequency, WindowSeconds: 3600, Threshold: 1}},
		observations: []poison.Observation{
			{SubjectIP: "10.155.9.9", DstIP: "10.155.32.11", At: now.Add(-time.Minute)},
		},
	}
	server := &Server{reader: fake}
	server.processDestinationTargets(now)
	if len(fake.written) != 0 || len(fake.evidence) != 0 {
		t.Fatalf("a disabled rule must produce nothing: %+v %+v", fake.written, fake.evidence)
	}
}
