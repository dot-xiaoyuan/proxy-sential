package risk

import (
	"bytes"
	"encoding/json"
	"strings"
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
		ev("weak-ua", "10.0.0.1", "multi_user_agent", 22, 0.35),
		ev("strong-2", "10.0.0.1", "multi_ja3_ja4", 30, 0.75),
		ev("strong-3", "10.0.0.1", "device_signal_conflict", 33, 0.68),
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

func TestInspectMultiUserAgentIsWeakEvidence(t *testing.T) {
	input := evidenceInput(
		ev("weak-ua", "10.0.0.1", "multi_user_agent", 35, 0.35),
		ev("weak-port", "10.0.0.1", "port_distribution", 20, 0.65),
	)

	snapshot, err := Inspect(bytes.NewReader(input), InspectOptions{IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Score != 45 || snapshot.Level != "suspicious" {
		t.Fatalf("UA weak evidence should not confirm risk: %+v", snapshot)
	}
}

func TestInspectEncryptedTunnelBehaviorIsWeakEvidence(t *testing.T) {
	input := evidenceInput(
		ev("quic-1", "10.0.0.1", "encrypted_tunnel_behavior", 25, 0.45),
		ev("quic-2", "10.0.0.1", "encrypted_tunnel_behavior", 25, 0.45),
	)

	snapshot, err := Inspect(bytes.NewReader(input), InspectOptions{IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Score != 29 || snapshot.Level != "normal" || snapshot.RecommendedAction != "record" {
		t.Fatalf("encrypted transport behavior must not confirm risk alone: %+v", snapshot)
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

func TestBatchBuildsAccountSubjectSnapshot(t *testing.T) {
	input := evidenceInput(
		accountEv("acct-mac", "2026000123", "account_concurrent_macs", 70, 0.92),
		accountEv("acct-access", "2026000123", "account_concurrent_access", 58, 0.82),
	)

	result, err := Batch(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Snapshots) != 1 {
		t.Fatalf("expected 1 account snapshot, got %+v", result.Snapshots)
	}
	snapshot := result.Snapshots[0]
	if snapshot.SubjectType != "account" || snapshot.SubjectID != "2026000123" || snapshot.AccountID != "2026000123" || snapshot.IP != "" {
		t.Fatalf("unexpected account subject snapshot: %+v", snapshot)
	}
	if snapshot.Score != 100 || snapshot.Level != "confirmed" || snapshot.RecommendedAction != "shadow_confirm_review" {
		t.Fatalf("unexpected account risk level: %+v", snapshot)
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

func TestApplyNegativeEvidenceDowngradesAndPreservesRawRisk(t *testing.T) {
	snapshot := Snapshot{
		IP:                "10.0.0.8",
		Score:             85,
		Level:             "confirmed",
		Summary:           "confirmed 级别风险由 strong evidence 贡献",
		RecommendedAction: "shadow_confirm_review",
	}

	adjusted := ApplyNegativeEvidence(snapshot, []NegativeEvidence{
		{Type: "manual_false_positive", Source: "label", Reason: "人工复核误报", ScoreDelta: -80, MaxScore: 20, LevelCap: "normal"},
	})

	if adjusted.Score != 5 || adjusted.Level != "normal" || adjusted.RecommendedAction != "record" {
		t.Fatalf("expected false positive label to downgrade risk, got %+v", adjusted)
	}
	if adjusted.RawScore != 85 || adjusted.RawLevel != "confirmed" {
		t.Fatalf("expected raw risk to be preserved, got %+v", adjusted)
	}
	if len(adjusted.NegativeEvidence) != 1 || adjusted.NegativeEvidence[0].Type != "manual_false_positive" {
		t.Fatalf("expected negative evidence metadata, got %+v", adjusted.NegativeEvidence)
	}
	if !strings.Contains(adjusted.Summary, "已应用负证据降权") {
		t.Fatalf("expected summary to explain downgrade, got %q", adjusted.Summary)
	}
}

func TestApplyNegativeEvidenceNeedsMoreDataCapsConfirmedAtHigh(t *testing.T) {
	snapshot := Snapshot{
		IP:                "10.0.0.8",
		Score:             90,
		Level:             "confirmed",
		Summary:           "confirmed risk",
		RecommendedAction: "shadow_confirm_review",
	}

	adjusted := ApplyNegativeEvidence(snapshot, []NegativeEvidence{
		{Type: "needs_more_data", Source: "label", Reason: "样本不足", ScoreDelta: -5, LevelCap: "high"},
	})

	if adjusted.Level != "high" || adjusted.Score != 79 || adjusted.RecommendedAction != "shadow_manual_review" {
		t.Fatalf("expected needs_more_data to cap confirmed at high, got %+v", adjusted)
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
		EvidenceID:  id,
		IP:          ip,
		SubjectType: "ip",
		SubjectID:   ip,
		Type:        evidenceType,
		Window:      "10m0s",
		Score:       score,
		Confidence:  confidence,
		Severity:    "medium",
		Reason:      "test evidence",
		Samples:     []string{"sample"},
		CreatedAt:   "2026-07-24T13:20:00Z",
	}
}

func accountEv(id, accountID, evidenceType string, score int, confidence float64) evidence.Evidence {
	return evidence.Evidence{
		EvidenceID:  id,
		SubjectType: "account",
		SubjectID:   accountID,
		AccountID:   accountID,
		Type:        evidenceType,
		Window:      "10m0s",
		Score:       score,
		Confidence:  confidence,
		Severity:    "high",
		Reason:      "test account evidence",
		Samples:     []string{"sample"},
		CreatedAt:   "2026-07-24T13:20:00Z",
	}
}
