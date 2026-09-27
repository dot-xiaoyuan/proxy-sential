package evaluation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

func TestCompareRuleFilesRejectsReviewedRegression(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	before := write("before.json", risk.BatchResult{Snapshots: []risk.Snapshot{{IP: "192.0.2.1", Level: "high", Score: 80, RawScore: 85, Confidence: .9, Window: "10m", EvidenceIDs: []string{"e-1"}, Summary: "rule match"}}})
	after := write("after.json", risk.BatchResult{Snapshots: []risk.Snapshot{{IP: "192.0.2.1", Level: "normal", Score: 20, RawScore: 85, Confidence: .9, Window: "10m", EvidenceIDs: []string{"e-1"}, Summary: "negative evidence"}}})
	labels := write("labels.jsonl", store.Label{TargetType: "ip", TargetID: "192.0.2.1", Label: "confirmed_proxy", Reason: "人工确认"})
	evidencePath := write("evidence.json", evidence.Result{Evidence: []evidence.Evidence{{EvidenceID: "e-1", Type: "vpn_proxy_rule_match"}}})
	report, err := CompareRuleFiles(before, after, labels, evidencePath, "v1", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if report.Pass || report.Regressions != 1 || report.Items[0].Candidate.RawScore != 85 || report.Items[0].EvidenceTypes[0] != "vpn_proxy_rule_match" {
		t.Fatalf("unexpected rule comparison: %+v", report)
	}
}

func TestBuildRuleCandidateAppliesVersionedNegativeEvidence(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	policyPath := filepath.Join(dir, "policy.json")
	outputPath := filepath.Join(dir, "candidate.json")
	evidenceData, _ := json.Marshal(evidence.Result{Evidence: []evidence.Evidence{{EvidenceID: "e-1", IP: "192.0.2.8", SubjectType: "ip", SubjectID: "192.0.2.8", Type: "vpn_proxy_rule_match", Score: 90, Confidence: .95, Window: "10m", Reason: "规则命中", CreatedAt: "2026-09-27T09:00:00Z"}}})
	policyData, _ := json.Marshal(RuleCandidate{Version: "t11-candidate-v1", NegativeBySubject: map[string][]risk.NegativeEvidence{"ip:192.0.2.8": {{Type: "campus_vpn", Source: "manual_review", Reason: "校园 VPN", ScoreDelta: -50}}}})
	for path, data := range map[string][]byte{evidencePath: evidenceData, policyPath: policyData} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := BuildRuleCandidate(evidencePath, policyPath, outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Snapshots) != 1 || batch.Snapshots[0].RawScore == 0 || batch.Snapshots[0].Score >= batch.Snapshots[0].RawScore || len(batch.Snapshots[0].NegativeEvidence) != 1 {
		t.Fatalf("candidate not applied: %+v", batch)
	}
}
