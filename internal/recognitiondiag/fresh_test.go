package recognitiondiag

import (
	"testing"
	"time"
)

func TestFreshDecisionWaitsForEveryGenerationAndKeepsDeadline(t *testing.T) {
	accepted := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	input := Input{Features: 1, ValidUntil: accepted.Add(time.Hour), Targets: []Target{{Endpoint: "a", Generation: 2}, {Endpoint: "b", Generation: 3}}}
	jobs := []Job{{Endpoint: "a", Processed: 2, CompletedAt: accepted.Add(2 * time.Second), Reason: "conflict", Candidates: 1, Conclusions: 2}, {Endpoint: "b", Processed: 2}}
	pending := Evaluate(input, jobs, accepted, accepted.Add(6*time.Second))
	if pending.Status != "processing" || !pending.Overdue || !pending.CompletedAt.IsZero() {
		t.Fatalf("premature completion: %+v", pending)
	}
	jobs[1] = Job{Endpoint: "b", Processed: 3, CompletedAt: accepted.Add(7 * time.Second)}
	done := Evaluate(input, jobs, accepted, accepted.Add(10*time.Second))
	if done.Status != "conflict" || !done.Overdue || !done.CompletedAt.Equal(accepted.Add(7*time.Second)) {
		t.Fatalf("lost original deadline: %+v", done)
	}
}

func TestFreshDecisionDoesNotInventAttributionOrCurrentEvidence(t *testing.T) {
	accepted := time.Now().UTC()
	input := Input{Features: 1, ValidUntil: accepted.Add(time.Second)}
	if got := Evaluate(input, nil, accepted, accepted); got.Status != "unattributed" {
		t.Fatalf("guessed attribution: %+v", got)
	}
	if got := Evaluate(input, nil, accepted, accepted.Add(2*time.Second)); got.Status != "unattributed_expired" {
		t.Fatalf("expired wait never ends: %+v", got)
	}
	input.Targets = []Target{{Endpoint: "a", Generation: 1}}
	jobs := []Job{{Endpoint: "a", Processed: 1, CompletedAt: accepted.Add(2 * time.Second), Candidates: 1, Conclusions: 3}}
	if got := Evaluate(input, jobs, accepted, accepted.Add(3*time.Second)); got.Status != "expired" || got.Conclusions != 0 || got.Candidates != 0 {
		t.Fatalf("stale evidence counted: %+v", got)
	}
	input.Withdrawn = true
	if got := Evaluate(input, jobs, accepted, accepted.Add(3*time.Second)); got.Status != "withdrawn" || got.Conclusions != 0 {
		t.Fatalf("withdrawal not tracked: %+v", got)
	}
}

func TestFreshDecisionSeparatesInsufficientEvidenceFromFailures(t *testing.T) {
	accepted := time.Now().UTC()
	input := Input{Targets: []Target{{Endpoint: "a", Generation: 4}}}
	jobs := []Job{{Endpoint: "a", Processed: 3, Error: "retry failure"}}
	if got := Evaluate(input, jobs, accepted, accepted.Add(6*time.Second)); got.Status != "processing" || got.Error != "retry failure" || !got.Overdue {
		t.Fatalf("failure hidden: %+v", got)
	}
	jobs[0] = Job{Endpoint: "a", Processed: 4, CompletedAt: accepted.Add(time.Second)}
	if got := Evaluate(input, jobs, accepted, accepted.Add(6*time.Second)); got.Status != "insufficient_evidence" || got.Overdue {
		t.Fatalf("observer delay changed latency: %+v", got)
	}
}
