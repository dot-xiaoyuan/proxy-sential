package evaluation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

type RuleSnapshotView struct {
	Level       string   `json:"level"`
	RawScore    int      `json:"raw_score"`
	Score       int      `json:"score"`
	Confidence  float64  `json:"confidence"`
	Window      string   `json:"window"`
	Explanation string   `json:"explanation"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type RuleComparisonItem struct {
	Subject       string           `json:"subject"`
	ReviewStatus  string           `json:"review_status,omitempty"`
	ReviewReason  string           `json:"review_reason,omitempty"`
	EvidenceTypes []string         `json:"evidence_types"`
	Baseline      RuleSnapshotView `json:"baseline"`
	Candidate     RuleSnapshotView `json:"candidate"`
	LevelChanged  bool             `json:"level_changed"`
	ScoreDelta    int              `json:"score_delta"`
	Regression    string           `json:"regression,omitempty"`
}

type RuleComparisonReport struct {
	BaselineVersion       string               `json:"baseline_version"`
	CandidateVersion      string               `json:"candidate_version"`
	Pass                  bool                 `json:"pass"`
	Compared              int                  `json:"compared"`
	Reviewed              int                  `json:"reviewed"`
	Changed               int                  `json:"changed"`
	Regressions           int                  `json:"regressions"`
	FalsePositiveReasons  []Count              `json:"false_positive_reasons"`
	FalsePositiveEvidence []Count              `json:"false_positive_evidence"`
	Items                 []RuleComparisonItem `json:"items"`
}

func CompareRuleFiles(baselinePath, candidatePath, labelsPath, evidencePath, baselineVersion, candidateVersion string) (RuleComparisonReport, error) {
	report := RuleComparisonReport{BaselineVersion: baselineVersion, CandidateVersion: candidateVersion, Items: []RuleComparisonItem{}, FalsePositiveReasons: []Count{}, FalsePositiveEvidence: []Count{}}
	if baselineVersion == "" || candidateVersion == "" || baselineVersion == candidateVersion {
		return report, fmt.Errorf("distinct baseline and candidate versions are required")
	}
	baseline, err := readSnapshots(baselinePath)
	if err != nil {
		return report, err
	}
	candidate, err := readSnapshots(candidatePath)
	if err != nil {
		return report, err
	}
	labels, err := readRuleLabels(labelsPath)
	if err != nil {
		return report, err
	}
	types, err := readEvidenceTypes(evidencePath)
	if err != nil {
		return report, err
	}
	if len(baseline) == 0 || len(baseline) != len(candidate) {
		return report, fmt.Errorf("baseline and candidate must contain the same nonempty subject set")
	}
	reasons, evidenceCounts := map[string]int{}, map[string]int{}
	keys := make([]string, 0, len(baseline))
	for key := range baseline {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		before := baseline[key]
		after, ok := candidate[key]
		if !ok {
			return report, fmt.Errorf("candidate lacks subject %s", key)
		}
		item := RuleComparisonItem{Subject: key, Baseline: snapshotView(before), Candidate: snapshotView(after), LevelChanged: before.Level != after.Level, ScoreDelta: after.Score - before.Score, EvidenceTypes: []string{}}
		if item.LevelChanged || item.ScoreDelta != 0 {
			report.Changed++
		}
		if label, found := labels[key]; found {
			item.ReviewStatus, item.ReviewReason = label.Label, label.Reason
			report.Reviewed++
			switch label.Label {
			case "confirmed", "confirmed_proxy":
				if riskRank(after.Level) < riskRank(before.Level) {
					item.Regression = "confirmed risk level decreased"
				}
			case "false_positive", "benign":
				reasons[label.Reason]++
				if riskRank(after.Level) > riskRank(before.Level) {
					item.Regression = "false positive risk level increased"
				}
			}
		}
		seen := map[string]bool{}
		for _, id := range after.EvidenceIDs {
			if kind := types[id]; kind != "" && !seen[kind] {
				item.EvidenceTypes = append(item.EvidenceTypes, kind)
				seen[kind] = true
				if item.ReviewStatus == "false_positive" || item.ReviewStatus == "benign" {
					evidenceCounts[kind]++
				}
			}
		}
		sort.Strings(item.EvidenceTypes)
		if item.Regression != "" {
			report.Regressions++
		}
		report.Items = append(report.Items, item)
	}
	report.Compared = len(report.Items)
	report.Pass = report.Regressions == 0 && report.Reviewed > 0 && report.Changed > 0
	report.FalsePositiveReasons = sortedCounts(reasons, 10)
	report.FalsePositiveEvidence = sortedCounts(evidenceCounts, 10)
	return report, nil
}

func snapshotSubject(item risk.Snapshot) string {
	if item.SubjectType != "" && item.SubjectID != "" {
		return strings.ToLower(item.SubjectType) + ":" + item.SubjectID
	}
	if item.AccountID != "" {
		return "account:" + item.AccountID
	}
	if item.EndpointID != "" {
		return "endpoint:" + item.EndpointID
	}
	return "ip:" + item.IP
}

func snapshotView(item risk.Snapshot) RuleSnapshotView {
	return RuleSnapshotView{Level: item.Level, RawScore: item.RawScore, Score: item.Score, Confidence: item.Confidence, Window: item.Window, Explanation: item.Summary, EvidenceIDs: append([]string{}, item.EvidenceIDs...)}
}

func riskRank(level string) int {
	switch level {
	case "confirmed":
		return 3
	case "high":
		return 2
	case "suspicious":
		return 1
	default:
		return 0
	}
}

func readSnapshots(path string) (map[string]risk.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var batch risk.BatchResult
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, err
	}
	items := make(map[string]risk.Snapshot, len(batch.Snapshots))
	for _, item := range batch.Snapshots {
		key := snapshotSubject(item)
		if _, exists := items[key]; key == "ip:" || exists {
			return nil, fmt.Errorf("invalid or duplicate subject %s", key)
		}
		items[key] = item
	}
	return items, nil
}

func readRuleLabels(path string) (map[string]store.Label, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := map[string]store.Label{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var item store.Label
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return nil, err
		}
		key := strings.ToLower(item.TargetType) + ":" + item.TargetID
		if current, ok := result[key]; !ok || item.CreatedAt > current.CreatedAt {
			result[key] = item
		}
	}
	return result, scanner.Err()
}

func readEvidenceTypes(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result evidence.Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	types := map[string]string{}
	for _, item := range result.Evidence {
		types[item.EvidenceID] = item.Type
	}
	return types, nil
}
