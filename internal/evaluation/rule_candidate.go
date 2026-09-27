package evaluation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

// RuleCandidate is an offline-only replay policy. It never changes the live
// rule engine or enables an enforcement action.
type RuleCandidate struct {
	Version            string                             `json:"version"`
	EvidenceScoreDelta map[string]int                     `json:"evidence_score_delta,omitempty"`
	NegativeBySubject  map[string][]risk.NegativeEvidence `json:"negative_by_subject,omitempty"`
}

func BuildRuleCandidate(evidencePath, policyPath, outputPath string) (risk.BatchResult, error) {
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return risk.BatchResult{}, err
	}
	var policy RuleCandidate
	if err := json.Unmarshal(policyData, &policy); err != nil {
		return risk.BatchResult{}, fmt.Errorf("decode candidate policy: %w", err)
	}
	if strings.TrimSpace(policy.Version) == "" || (len(policy.EvidenceScoreDelta) == 0 && len(policy.NegativeBySubject) == 0) {
		return risk.BatchResult{}, fmt.Errorf("candidate version and at least one adjustment are required")
	}
	for kind, delta := range policy.EvidenceScoreDelta {
		if kind == "" || delta < -100 || delta > 100 {
			return risk.BatchResult{}, fmt.Errorf("invalid evidence score adjustment for %q", kind)
		}
	}
	for subject, items := range policy.NegativeBySubject {
		if !strings.Contains(subject, ":") || len(items) == 0 {
			return risk.BatchResult{}, fmt.Errorf("invalid negative evidence subject %q", subject)
		}
		for _, item := range items {
			if item.Type == "" || item.Source == "" || item.Reason == "" || item.ScoreDelta > 0 || item.LevelCap != "" && item.LevelCap != "normal" && item.LevelCap != "suspicious" && item.LevelCap != "high" {
				return risk.BatchResult{}, fmt.Errorf("invalid negative evidence for %q", subject)
			}
		}
	}
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		return risk.BatchResult{}, err
	}
	var result evidence.Result
	if err := json.Unmarshal(data, &result); err != nil {
		return risk.BatchResult{}, fmt.Errorf("decode evidence: %w", err)
	}
	for i := range result.Evidence {
		if delta := policy.EvidenceScoreDelta[result.Evidence[i].Type]; delta != 0 {
			result.Evidence[i].Score += delta
			if result.Evidence[i].Score < 0 {
				result.Evidence[i].Score = 0
			}
			if result.Evidence[i].Score > 100 {
				result.Evidence[i].Score = 100
			}
			result.Evidence[i].Reason += fmt.Sprintf("；候选版本 %s 对该证据类型调整 %+d 分", policy.Version, delta)
		}
	}
	data, err = json.Marshal(result)
	if err != nil {
		return risk.BatchResult{}, err
	}
	batch, err := risk.Batch(bytes.NewReader(data))
	if err != nil {
		return risk.BatchResult{}, err
	}
	seen := map[string]bool{}
	for i := range batch.Snapshots {
		key := snapshotSubject(batch.Snapshots[i])
		seen[key] = true
		batch.Snapshots[i] = risk.ApplyNegativeEvidence(batch.Snapshots[i], policy.NegativeBySubject[key])
	}
	for subject := range policy.NegativeBySubject {
		if !seen[subject] {
			return risk.BatchResult{}, fmt.Errorf("candidate references missing subject %s", subject)
		}
	}
	data, err = json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return risk.BatchResult{}, err
	}
	if err := os.WriteFile(outputPath, append(data, '\n'), 0o600); err != nil {
		return risk.BatchResult{}, err
	}
	return batch, nil
}
