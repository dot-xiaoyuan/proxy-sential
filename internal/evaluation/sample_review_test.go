package evaluation

import (
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

func TestShadowRunLabelDoesNotReviewOtherObjects(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	snapshots := []risk.Snapshot{
		{IP: "10.0.0.1", SubjectType: "ip", SubjectID: "10.0.0.1", Level: "high", EvidenceIDs: []string{"a"}, UpdatedAt: now.Format(time.RFC3339)},
		{IP: "10.0.0.2", SubjectType: "ip", SubjectID: "10.0.0.2", Level: "high", EvidenceIDs: []string{"b"}, UpdatedAt: now.Format(time.RFC3339)},
	}
	writeEvaluationRun(t, dir, "run-1", now, snapshots, []evidence.Evidence{{EvidenceID: "a"}, {EvidenceID: "b"}})
	writeLabels(t, filepath.Join(dir, "labels.jsonl"), []store.Label{{TargetType: "risk_snapshot", TargetID: "run-1", Label: "confirmed_proxy", EvidenceIDs: []string{"a"}, CreatedAt: now.Format(time.RFC3339)}})
	runs, err := readRuns(ShadowOptions{ShadowDir: dir}, mustReadReviewLabels(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if runs[0].samples[0].ReviewStatus != "confirmed_proxy" || runs[0].samples[1].ReviewStatus != "unreviewed" {
		t.Fatalf("run label leaked between objects: %+v", runs[0].samples)
	}
}

func mustReadReviewLabels(t *testing.T, dir string) []store.Label {
	t.Helper()
	labels, err := readLabels(filepath.Join(dir, "labels.jsonl"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return labels
}

func TestSampleReviewIdentityAndAmbiguousLegacyEvidence(t *testing.T) {
	a := Sample{Date: "2026-09-30", SourceRunID: "run-1", SubjectType: "ip", SubjectID: "10.0.0.1", SnapshotTime: "2026-09-30T12:00:00Z", EvidenceIDs: []string{"shared"}, ReviewStatus: "unreviewed"}
	b := a
	b.SubjectID = "10.0.0.2"
	if SampleID(a) == SampleID(b) {
		t.Fatal("sample identity must include the object")
	}
	equivalent := a
	equivalent.SnapshotTime = "2026-09-30T20:00:00+08:00"
	if SampleID(a) != SampleID(equivalent) {
		t.Fatal("equivalent timestamps changed sample identity")
	}
	labels := []store.Label{{TargetType: "risk_snapshot", TargetID: "run-1", Label: "confirmed_proxy", EvidenceIDs: []string{"shared"}, CreatedAt: "2026-09-30T13:00:00Z"}}
	ApplySampleReview(&a, []Sample{a, b}, labels)
	if a.ReviewStatus != "unreviewed" || !a.ReviewConflict {
		t.Fatalf("ambiguous label accepted: %+v", a)
	}
	labels = append(labels, store.Label{TargetType: "risk_snapshot", TargetID: SampleID(a), Label: "false_positive", EvidenceIDs: []string{"shared"}, CreatedAt: "2026-09-30T14:00:00Z"})
	ApplySampleReview(&a, []Sample{a, b}, labels)
	ApplySampleReview(&b, []Sample{a, b}, labels)
	if a.ReviewStatus != "false_positive" || a.ReviewConflict || b.ReviewStatus != "unreviewed" {
		t.Fatalf("stable label leaked or conflict retained: %+v %+v", a, b)
	}
}

func TestSampleReviewOrdersLabelsByInstant(t *testing.T) {
	sample := Sample{Date: "2026-09-30", SourceRunID: "run-1", SubjectType: "account", SubjectID: "staff-001", SnapshotTime: "2026-09-30T12:00:00Z"}
	labels := []store.Label{
		{TargetType: "risk_snapshot", TargetID: SampleID(sample), Label: "confirmed_proxy", CreatedAt: "2026-09-30T21:00:00+08:00"},
		{TargetType: "risk_snapshot", TargetID: SampleID(sample), Label: "false_positive", CreatedAt: "2026-09-30T14:00:00Z"},
	}
	ApplySampleReview(&sample, []Sample{sample}, labels)
	if sample.ReviewStatus != "false_positive" {
		t.Fatalf("latest review must compare instants rather than timezone strings: %+v", sample)
	}
}
