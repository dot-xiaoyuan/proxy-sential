package evaluation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/shadow"
	"proxy-sentinel/internal/store"
)

func TestEvaluateShadowCompletesSevenDayReviewedWindow(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	labels := []store.Label{}
	for day := 0; day < 7; day++ {
		finished := start.AddDate(0, 0, day)
		snapshots := []risk.Snapshot{}
		evidenceItems := []evidence.Evidence{}
		for levelIndex, level := range evaluationLevels {
			ip := fmt.Sprintf("10.20.%d.%d", day+1, levelIndex+1)
			evidenceID := fmt.Sprintf("evidence-%d-%s", day, level)
			snapshots = append(snapshots, risk.Snapshot{
				IP: ip, SubjectType: "ip", SubjectID: ip, Level: level, Score: 90 - levelIndex*20,
				Confidence: 0.9, EvidenceIDs: []string{evidenceID}, UpdatedAt: finished.Format(time.RFC3339Nano),
			})
			evidenceItems = append(evidenceItems, evidence.Evidence{EvidenceID: evidenceID, IP: ip, Type: "vpn_proxy_rule_match"})
			labelKind, reason := "confirmed", "人工确认代理"
			if level == "normal" {
				labelKind, reason = "benign", "视频会议"
			}
			labels = append(labels, store.Label{
				LabelID: fmt.Sprintf("label-%d-%s", day, level), TargetType: "ip", TargetID: ip,
				Label: labelKind, Reason: reason, EvidenceIDs: []string{evidenceID}, CreatedBy: "operator",
				CreatedAt: finished.Add(time.Hour).Format(time.RFC3339Nano),
			})
		}
		writeEvaluationRun(t, dir, fmt.Sprintf("run-%02d", day), finished, snapshots, evidenceItems)
	}
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), labels)
	exportDir := filepath.Join(dir, "exports")

	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 7, SamplesPerDay: 2, ExportDir: exportDir, Now: start.AddDate(0, 0, 7)})
	if err != nil {
		t.Fatalf("evaluate shadow: %v", err)
	}
	if !report.Ready || report.ObservedDays != 7 || report.LongestContinuousDays != 7 || report.DaysWithReviews != 7 {
		t.Fatalf("expected ready seven-day report, got %+v", report)
	}
	if report.ReviewedSnapshotCount != 28 || len(report.DailySampleExports) != 7 {
		t.Fatalf("expected all samples reviewed and daily exports, got %+v", report)
	}
	if len(report.FalsePositiveReasons) == 0 || report.FalsePositiveReasons[0].Value != "视频会议" {
		t.Fatalf("expected false-positive reason aggregation, got %+v", report.FalsePositiveReasons)
	}
	if len(report.FalsePositiveEvidence) == 0 || report.FalsePositiveEvidence[0].Value != "vpn_proxy_rule_match" {
		t.Fatalf("expected evidence aggregation, got %+v", report.FalsePositiveEvidence)
	}
}

// writeAccuracyFixture writes seven reviewed days with one sample per level.
// The first falsePositiveCandidates candidate samples are labelled false
// positive; normal samples are labelled benign ground truth.
func writeAccuracyFixture(t *testing.T, dir string, falsePositiveCandidates int) {
	t.Helper()
	start := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	labels := []store.Label{}
	candidateIndex := 0
	for day := 0; day < 7; day++ {
		finished := start.AddDate(0, 0, day)
		snapshots := []risk.Snapshot{}
		evidenceItems := []evidence.Evidence{}
		for levelIndex, level := range evaluationLevels {
			ip := fmt.Sprintf("10.30.%d.%d", day+1, levelIndex+1)
			evidenceID := fmt.Sprintf("evidence-%d-%s", day, level)
			snapshots = append(snapshots, risk.Snapshot{
				IP: ip, SubjectType: "ip", SubjectID: ip, Level: level, Score: 90 - levelIndex*20,
				Confidence: 0.9, EvidenceIDs: []string{evidenceID}, UpdatedAt: finished.Format(time.RFC3339Nano),
			})
			evidenceItems = append(evidenceItems, evidence.Evidence{EvidenceID: evidenceID, IP: ip, Type: "vpn_proxy_rule_match"})
			labelKind, reason := "confirmed", "人工确认代理"
			if level == "normal" {
				labelKind, reason = "benign", "视频会议"
			} else {
				if candidateIndex < falsePositiveCandidates {
					labelKind, reason = "false_positive", "普通远程办公"
				}
				candidateIndex++
			}
			labels = append(labels, store.Label{
				LabelID: fmt.Sprintf("label-%d-%s", day, level), TargetType: "ip", TargetID: ip,
				Label: labelKind, Reason: reason, EvidenceIDs: []string{evidenceID}, CreatedBy: "operator",
				CreatedAt: finished.Add(time.Hour).Format(time.RFC3339Nano),
			})
		}
		writeEvaluationRun(t, dir, fmt.Sprintf("run-%02d", day), finished, snapshots, evidenceItems)
	}
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), labels)
}

func TestEvaluateShadowAccuracyGatesBlockUntilGroundTruthIsSufficient(t *testing.T) {
	dir := t.TempDir()
	writeAccuracyFixture(t, dir, 0)
	report, err := EvaluateShadow(ShadowOptions{
		ShadowDir: dir, RequiredDays: 7, SamplesPerDay: 2,
		Now:                  time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC),
		MinPrecision:         0.95,
		MinNormalGroundTruth: 200,
		MinCandidateReviews:  200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready {
		t.Fatalf("expected accuracy thresholds to block readiness: %+v", report)
	}
	if report.CandidateReviewed != 21 || report.NormalReviewed != 7 {
		t.Fatalf("unexpected ground-truth counts: %+v", report)
	}
	if report.CandidatePrecision != 1 {
		t.Fatalf("expected perfect candidate precision, got %v", report.CandidatePrecision)
	}
	if !containsBlock(report.Blockers, "候选复核仅 21 条") || !containsBlock(report.Blockers, "正常真值仅 7 条") {
		t.Fatalf("expected ground-truth blockers, got %+v", report.Blockers)
	}
	if containsBlock(report.Blockers, "候选准确率") {
		t.Fatalf("precision is 1.0 and must not be reported as failing: %+v", report.Blockers)
	}
}

func TestEvaluateShadowAccuracyGatesPassAtThreshold(t *testing.T) {
	dir := t.TempDir()
	writeAccuracyFixture(t, dir, 0)
	report, err := EvaluateShadow(ShadowOptions{
		ShadowDir: dir, RequiredDays: 7, SamplesPerDay: 2,
		Now:                  time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC),
		MinPrecision:         0.95,
		MinNormalGroundTruth: 7,
		MinCandidateReviews:  21,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready {
		t.Fatalf("expected thresholds to pass: %+v", report.Blockers)
	}
}

func TestEvaluateShadowAccuracyGateRejectsLowPrecision(t *testing.T) {
	dir := t.TempDir()
	// 3 of 21 candidates are false positives: 18/21 = 0.857 < 0.95.
	writeAccuracyFixture(t, dir, 3)
	report, err := EvaluateShadow(ShadowOptions{
		ShadowDir: dir, RequiredDays: 7, SamplesPerDay: 2,
		Now:                  time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC),
		MinPrecision:         0.95,
		MinNormalGroundTruth: 7,
		MinCandidateReviews:  21,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.CandidatePrecision >= 0.95 {
		t.Fatalf("expected precision below the threshold, got %v", report.CandidatePrecision)
	}
	if report.Ready || !containsBlock(report.Blockers, "候选准确率") {
		t.Fatalf("expected precision blocker, got %+v", report)
	}
}

func TestEvaluateShadowAccuracyGatesDisabledByZero(t *testing.T) {
	dir := t.TempDir()
	writeAccuracyFixture(t, dir, 0)
	report, err := EvaluateShadow(ShadowOptions{
		ShadowDir: dir, RequiredDays: 7, SamplesPerDay: 2,
		Now: time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready {
		t.Fatalf("zero-valued gates must not change existing behavior: %+v", report.Blockers)
	}
}

func TestCandidateAccuracyExcludesNeedsMoreData(t *testing.T) {
	levels := map[string]ReviewStats{
		"confirmed":  {Reviewed: 4, Confirmed: 2, FalsePositive: 1, Benign: 1},
		"high":       {Reviewed: 2, Confirmed: 1, NeedsMoreData: 1},
		"suspicious": {Reviewed: 1, NeedsMoreData: 1},
		"normal":     {Reviewed: 3, Benign: 3},
	}
	reviewed, confirmed, value := candidateAccuracy(levels)
	if reviewed != 7 || confirmed != 3 {
		t.Fatalf("unexpected candidate counts: reviewed=%d confirmed=%d", reviewed, confirmed)
	}
	// decided = 2 + 1 + 1 + 1 = 5; precision = 3/5.
	if value != 0.6 {
		t.Fatalf("needs_more_data must not enter the precision denominator, got %v", value)
	}
}

func containsBlock(blockers []string, needle string) bool {
	for _, blocker := range blockers {
		if strings.Contains(blocker, needle) {
			return true
		}
	}
	return false
}

func TestEvaluateShadowCountsConfirmedProxyLabelAsReviewed(t *testing.T) {
	dir := t.TempDir()
	finished := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	writeEvaluationRun(t, dir, "run-01", finished, []risk.Snapshot{{
		IP: "10.20.1.9", SubjectType: "ip", SubjectID: "10.20.1.9", Level: "confirmed", Score: 96,
		EvidenceIDs: []string{"evidence-1"}, UpdatedAt: finished.Format(time.RFC3339Nano),
	}}, []evidence.Evidence{{EvidenceID: "evidence-1", IP: "10.20.1.9", Type: "vpn_proxy_rule_match"}})
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), []store.Label{{
		LabelID: "label-1", TargetType: "ip", TargetID: "10.20.1.9", Label: "confirmed_proxy",
		EvidenceIDs: []string{"evidence-1"}, CreatedAt: finished.Add(time.Minute).Format(time.RFC3339Nano),
	}})
	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 1, Now: finished.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.ReviewedSnapshotCount != 1 || report.LevelStats["confirmed"].Confirmed != 1 {
		t.Fatalf("expected confirmed_proxy to satisfy review accounting: %+v", report)
	}
}

func TestEvaluateShadowDoesNotReuseSubjectLabelAcrossDifferentEvidence(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	for day := 0; day < 2; day++ {
		finished := start.AddDate(0, 0, day)
		evidenceID := fmt.Sprintf("evidence-%d", day)
		writeEvaluationRun(t, dir, fmt.Sprintf("run-%d", day), finished, []risk.Snapshot{{
			IP: "10.20.1.9", SubjectType: "ip", SubjectID: "10.20.1.9", Level: "high", Score: 80,
			EvidenceIDs: []string{evidenceID}, UpdatedAt: finished.Format(time.RFC3339Nano),
		}}, []evidence.Evidence{{EvidenceID: evidenceID, IP: "10.20.1.9", Type: "ttl_clusters"}})
	}
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), []store.Label{{
		LabelID: "label-1", TargetType: "ip", TargetID: "10.20.1.9", Label: "false_positive",
		EvidenceIDs: []string{"evidence-1"}, CreatedAt: start.AddDate(0, 0, 1).Add(time.Minute).Format(time.RFC3339Nano),
	}})
	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 2, Now: start.AddDate(0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	if report.ReviewedSnapshotCount != 1 || report.DaysWithReviews != 1 {
		t.Fatalf("subject label leaked across daily evidence snapshots: %+v", report)
	}
}

func TestEvaluateShadowReportsMissingRunsAndReviews(t *testing.T) {
	dir := t.TempDir()
	finished := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	writeEvaluationRun(t, dir, "run-01", finished, []risk.Snapshot{{
		IP: "10.20.1.1", Level: "high", Score: 80, EvidenceIDs: []string{"evidence-1"}, UpdatedAt: finished.Format(time.RFC3339Nano),
	}}, []evidence.Evidence{{EvidenceID: "evidence-1", IP: "10.20.1.1", Type: "vpn_proxy_rule_match"}})

	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 7, Now: finished})
	if err != nil {
		t.Fatalf("evaluate shadow: %v", err)
	}
	if report.Ready || report.LongestContinuousDays != 1 || len(report.MissingReviewBuckets) != 1 || len(report.Blockers) < 2 {
		t.Fatalf("expected incomplete evaluation blockers, got %+v", report)
	}
}

func TestEvaluateShadowDeduplicatesSubjectWithinDay(t *testing.T) {
	dir := t.TempDir()
	finished := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	for run := 0; run < 2; run++ {
		snapshotTime := finished.Add(time.Duration(run) * time.Hour)
		writeEvaluationRun(t, dir, fmt.Sprintf("run-%d", run), snapshotTime, []risk.Snapshot{{
			IP: "10.20.1.1", SubjectType: "ip", SubjectID: "10.20.1.1", Level: "high", Score: 80 + run,
			EvidenceIDs: []string{"evidence-1"}, UpdatedAt: snapshotTime.Format(time.RFC3339Nano),
		}}, []evidence.Evidence{{EvidenceID: "evidence-1", IP: "10.20.1.1", Type: "vpn_proxy_rule_match"}})
	}

	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 1, Now: finished})
	if err != nil {
		t.Fatalf("evaluate shadow: %v", err)
	}
	if report.RiskSnapshotCount != 2 || report.EvaluatedSampleCount != 1 || report.LevelStats["high"].Total != 1 {
		t.Fatalf("expected one evaluated subject-day from two snapshots, got %+v", report)
	}
}

func TestEvaluateShadowWarnsWithoutBlockingForRecoveredCollectionNoise(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	labels := []store.Label{}
	for run := 0; run < 100; run++ {
		finished := start.Add(time.Duration(run) * time.Minute)
		ip := fmt.Sprintf("10.30.0.%d", run+1)
		writeEvaluationRun(t, dir, fmt.Sprintf("run-%03d", run), finished, []risk.Snapshot{{
			IP: ip, SubjectType: "ip", SubjectID: ip, Level: "normal", UpdatedAt: finished.Format(time.RFC3339Nano),
		}}, nil)
		labels = append(labels, store.Label{LabelID: fmt.Sprintf("label-%03d", run), TargetType: "risk_snapshot", TargetID: fmt.Sprintf("run-%03d", run), Label: "benign", CreatedAt: finished.Add(time.Second).Format(time.RFC3339Nano)})
	}
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), labels)
	firstSummaryPath := filepath.Join(dir, "runs", "run-000", "run-summary.json")
	var summary shadow.RunSummary
	data, err := os.ReadFile(firstSummaryPath)
	if err != nil || json.Unmarshal(data, &summary) != nil {
		t.Fatalf("read first run summary: %v", err)
	}
	summary.Truncated = true
	summary.Normalized.Malformed = 1
	summary.Normalized.Emitted = 999
	mustWriteEvaluationJSON(t, firstSummaryPath, summary)

	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 1, Now: start.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("evaluate shadow: %v", err)
	}
	if !report.Ready || len(report.CollectionWarnings) != 2 || report.TruncatedRunRate != 0.01 || report.MalformedEventRate >= 0.01 {
		t.Fatalf("expected recovered collection noise to warn without blocking, got %+v", report)
	}
}

func TestEvaluateShadowBlocksSustainedCollectionFailures(t *testing.T) {
	dir := t.TempDir()
	finished := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	writeEvaluationRun(t, dir, "run-01", finished, []risk.Snapshot{{IP: "10.40.0.1", Level: "normal", UpdatedAt: finished.Format(time.RFC3339Nano)}}, nil)
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), []store.Label{{LabelID: "label-1", TargetType: "risk_snapshot", TargetID: "run-01", Label: "benign", CreatedAt: finished.Add(time.Second).Format(time.RFC3339Nano)}})
	summaryPath := filepath.Join(dir, "runs", "run-01", "run-summary.json")
	var summary shadow.RunSummary
	data, err := os.ReadFile(summaryPath)
	if err != nil || json.Unmarshal(data, &summary) != nil {
		t.Fatalf("read run summary: %v", err)
	}
	summary.Truncated = true
	summary.Normalized.Malformed = 1
	mustWriteEvaluationJSON(t, summaryPath, summary)

	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 1, Now: finished})
	if err != nil {
		t.Fatalf("evaluate shadow: %v", err)
	}
	if report.Ready || report.TruncatedRunRate != 1 || report.MalformedEventRate <= 0.01 {
		t.Fatalf("expected sustained collection failures to block, got %+v", report)
	}
}

func writeEvaluationRun(t *testing.T, shadowDir, runID string, finished time.Time, snapshots []risk.Snapshot, evidenceItems []evidence.Evidence) {
	t.Helper()
	runDir := filepath.Join(shadowDir, "runs", runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("create run dir: %v", err)
	}
	summary := shadow.RunSummary{
		StartedAt: finished.Add(-time.Minute).Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano),
		RunDir: runDir, Normalized: suricata.Stats{Read: len(snapshots), Emitted: len(snapshots), ByType: map[string]int{"tls": len(snapshots)}}, EvidenceCount: len(evidenceItems), RiskCount: len(snapshots),
	}
	mustWriteEvaluationJSON(t, filepath.Join(runDir, "run-summary.json"), summary)
	mustWriteEvaluationJSON(t, filepath.Join(runDir, "risk-snapshots.json"), risk.BatchResult{Snapshots: snapshots})
	mustWriteEvaluationJSON(t, filepath.Join(runDir, "evidence.json"), evidence.Result{Evidence: evidenceItems})
}

func writeLabels(t *testing.T, path string, labels []store.Label) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create labels: %v", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, label := range labels {
		if err := encoder.Encode(label); err != nil {
			t.Fatalf("write label: %v", err)
		}
	}
}

func mustWriteEvaluationJSON(t *testing.T, path string, value any) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(value); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
