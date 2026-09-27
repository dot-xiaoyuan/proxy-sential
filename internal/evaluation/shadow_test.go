package evaluation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 7, SamplesPerDay: 2, ExportDir: exportDir, Now: start.AddDate(0, 0, 7), MinCandidateReviews: 14, MinNormalTruth: 7})
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

func TestShadowReviewRequiresMatchingEvidenceForEachDay(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	for day := 0; day < 2; day++ {
		when := start.AddDate(0, 0, day)
		id := fmt.Sprintf("evidence-day-%d", day)
		writeEvaluationRun(t, dir, fmt.Sprintf("run-%d", day), when, []risk.Snapshot{{IP: "192.0.2.20", SubjectType: "ip", SubjectID: "192.0.2.20", Level: "high", Score: 80, EvidenceIDs: []string{id}, UpdatedAt: when.Format(time.RFC3339Nano)}}, []evidence.Evidence{{EvidenceID: id, IP: "192.0.2.20", Type: "vpn_proxy_rule_match"}})
	}
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), []store.Label{{TargetType: "ip", TargetID: "192.0.2.20", Label: "confirmed_proxy", EvidenceIDs: []string{"evidence-day-0"}, CreatedAt: start.Add(48 * time.Hour).Format(time.RFC3339Nano)}})
	report, err := EvaluateShadow(ShadowOptions{ShadowDir: dir, RequiredDays: 2, MinCandidateReviews: 1, MinNormalTruth: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.DaysWithReviews != 1 || report.ReviewedSnapshotCount != 1 || len(report.MissingReviewBuckets) != 1 {
		t.Fatalf("one label was counted for another day's evidence: %+v", report)
	}
}

func TestShadowReviewDoesNotCrossSubjectTypes(t *testing.T) {
	snapshot := risk.Snapshot{IP: "192.0.2.30", SubjectType: "account", SubjectID: "student-30", AccountID: "student-30", EvidenceIDs: []string{"shared-evidence"}}
	ipLabel := store.Label{TargetType: "ip", TargetID: "192.0.2.30", Label: "benign", EvidenceIDs: []string{"shared-evidence"}}
	if _, found := latestMatchingLabel(snapshot, []store.Label{ipLabel}); found {
		t.Fatal("IP label reviewed an account subject")
	}
	accountLabel := store.Label{TargetType: "account", TargetID: "student-30", Label: "confirmed_proxy", EvidenceIDs: []string{"shared-evidence"}}
	if label, found := latestMatchingLabel(snapshot, []store.Label{ipLabel, accountLabel}); !found || label.TargetType != "account" {
		t.Fatalf("account review not selected: %+v found=%v", label, found)
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
