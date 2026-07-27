package risk

import (
	"bytes"
	"encoding/json"
	"testing"

	"proxy-sentinel/internal/evidence"
)

func TestInspectWeakEvidenceDoesNotEscalateBeyondSuspicious(t *testing.T) {
	input := evidenceInput(
		ev("weak-1", "10.0.0.1", "domain_diversity", 25, 0.65),
		ev("weak-2", "10.0.0.1", "port_distribution", 25, 0.65),
	)

	snapshot, err := Inspect(bytes.NewReader(input), InspectOptions{IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Score != 45 || snapshot.Level != "suspicious" || snapshot.RecommendedAction != "shadow_watch" {
		t.Fatalf("unexpected weak-only snapshot: %+v", snapshot)
	}
}

func TestInspectMultipleStrongEvidenceCanConfirm(t *testing.T) {
	input := evidenceInput(
		ev("strong-1", "10.0.0.1", "multi_user_agent", 35, 0.85),
		ev("strong-2", "10.0.0.1", "multi_ja3_ja4", 30, 0.75),
		ev("weak-1", "10.0.0.1", "port_distribution", 20, 0.65),
	)

	snapshot, err := Inspect(bytes.NewReader(input), InspectOptions{IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Score != 85 || snapshot.Level != "confirmed" || snapshot.RecommendedAction != "shadow_confirm_review" {
		t.Fatalf("unexpected confirmed snapshot: %+v", snapshot)
	}
	if len(snapshot.EvidenceIDs) != 3 {
		t.Fatalf("expected 3 evidence ids, got %+v", snapshot.EvidenceIDs)
	}
}

func TestInspectNoEvidenceReturnsNormal(t *testing.T) {
	input := evidenceInput(ev("other", "10.0.0.2", "multi_user_agent", 35, 0.85))

	snapshot, err := Inspect(bytes.NewReader(input), InspectOptions{IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Score != 0 || snapshot.Level != "normal" || snapshot.RecommendedAction != "record" {
		t.Fatalf("unexpected normal snapshot: %+v", snapshot)
	}
}

func TestBatchBuildsSnapshotsForEveryEvidenceIP(t *testing.T) {
	input := evidenceInput(
		ev("weak-1", "10.0.0.1", "domain_diversity", 25, 0.65),
		ev("weak-2", "10.0.0.1", "port_distribution", 25, 0.65),
		ev("strong-1", "10.0.0.2", "multi_user_agent", 35, 0.85),
		ev("strong-2", "10.0.0.2", "multi_ja3_ja4", 30, 0.75),
		ev("empty-ip", "", "multi_user_agent", 35, 0.85),
	)

	result, err := Batch(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %+v", result.Snapshots)
	}
	if result.Snapshots[0].IP != "10.0.0.1" || result.Snapshots[0].Level != "suspicious" {
		t.Fatalf("unexpected first snapshot: %+v", result.Snapshots[0])
	}
	if result.Snapshots[1].IP != "10.0.0.2" || result.Snapshots[1].Level != "high" {
		t.Fatalf("unexpected second snapshot: %+v", result.Snapshots[1])
	}
}

func TestListFiltersSortsAndLimitsSnapshots(t *testing.T) {
	batch := BatchResult{Snapshots: []Snapshot{
		{IP: "10.0.0.1", Score: 20, Level: "normal"},
		{IP: "10.0.0.2", Score: 45, Level: "suspicious"},
		{IP: "10.0.0.3", Score: 70, Level: "high"},
		{IP: "10.0.0.4", Score: 85, Level: "confirmed"},
		{IP: "10.0.0.5", Score: 65, Level: "high"},
	}}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}

	result, err := List(bytes.NewReader(data), ListOptions{MinLevel: "suspicious", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Snapshots) != 3 {
		t.Fatalf("expected 3 snapshots, got %+v", result.Snapshots)
	}
	expectedIPs := []string{"10.0.0.4", "10.0.0.3", "10.0.0.5"}
	for i, expected := range expectedIPs {
		if result.Snapshots[i].IP != expected {
			t.Fatalf("expected %s at %d, got %+v", expected, i, result.Snapshots)
		}
	}
}

func TestListRejectsUnknownMinimumLevel(t *testing.T) {
	_, err := List(bytes.NewReader([]byte(`{"snapshots":[]}`)), ListOptions{MinLevel: "critical"})
	if err == nil {
		t.Fatal("expected unknown min level to fail")
	}
}

func evidenceInput(items ...evidence.Evidence) []byte {
	result := evidence.Result{Evidence: items}
	data, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	return data
}

func ev(id, ip, evidenceType string, score int, confidence float64) evidence.Evidence {
	return evidence.Evidence{
		EvidenceID: id,
		IP:         ip,
		Type:       evidenceType,
		Window:     "10m0s",
		Score:      score,
		Confidence: confidence,
		Severity:   "medium",
		Reason:     "test evidence",
		Samples:    []string{"sample"},
		CreatedAt:  "2026-07-24T13:20:00Z",
	}
}
