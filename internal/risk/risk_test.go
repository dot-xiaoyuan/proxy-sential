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
