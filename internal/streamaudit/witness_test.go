package streamaudit

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func fixtureManifest() Manifest {
	return Manifest{
		Epoch: "epoch-a", SourceKind: "zeek-dhcp-binding", SourcePath: "/capture/dhcp.log", FileID: "file-a",
		StartOffset: 0, EndOffset: 200,
		Segments: []ExpectedSegment{
			{ID: strings.Repeat("a", 64), ProjectionSHA256: strings.Repeat("b", 64), EventCount: 2, StartOffset: 0, EndOffset: 100},
			{ID: strings.Repeat("c", 64), ProjectionSHA256: strings.Repeat("d", 64), EventCount: 1, StartOffset: 100, EndOffset: 200},
		},
	}
}

func fixtureWitnesses() []Witness {
	manifest := fixtureManifest()
	rows := make([]Witness, 0, len(manifest.Segments))
	for _, segment := range manifest.Segments {
		rows = append(rows, Witness{
			Found: true, ID: segment.ID, Epoch: manifest.Epoch, SourceKind: manifest.SourceKind,
			SourcePath: manifest.SourcePath, FileID: sql.NullString{String: manifest.FileID, Valid: true},
			StartOffset:      sql.NullInt64{Int64: segment.StartOffset, Valid: true},
			EndOffset:        sql.NullInt64{Int64: segment.EndOffset, Valid: true},
			ProjectionSHA256: segment.ProjectionSHA256, EventCount: segment.EventCount,
			ProjectedAt: time.Now().Add(-time.Second),
			FinalizedAt: sql.NullTime{Time: time.Now(), Valid: true},
		})
	}
	return rows
}

func TestWitnessAuditRejectsWrongSourceAndTimeOrder(t *testing.T) {
	rows := fixtureWitnesses()
	rows[0].Epoch = "other-epoch"
	rows[0].FileID.String = "other-file"
	rows[1].FinalizedAt.Time = rows[1].ProjectedAt.Add(-time.Second)
	report := Verify(fixtureManifest(), rows)
	for _, code := range []string{"source_identity_mismatch", "source_position_mismatch", "finalization_before_projection"} {
		if !hasIssue(report, code) {
			t.Fatalf("%s missing: %+v", code, report)
		}
	}
}

func TestWitnessAuditPassesOnlyListedFinalizedSegments(t *testing.T) {
	report := Verify(fixtureManifest(), fixtureWitnesses())
	if !report.WitnessConfirmed || len(report.Issues) != 0 || report.CleanupAllowed || report.ArchiveCoverage != "unverified" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestWitnessAuditRejectsManifestGapAndOverlap(t *testing.T) {
	for _, offset := range []int64{99, 101} {
		manifest := fixtureManifest()
		manifest.Segments[1].StartOffset = offset
		report := Verify(manifest, fixtureWitnesses())
		if report.WitnessConfirmed || !hasIssue(report, "manifest_position_gap_or_overlap") {
			t.Fatalf("offset %d: %+v", offset, report)
		}
	}
}

func TestWitnessAuditRejectsLegacyNullAndUnfinishedLane(t *testing.T) {
	rows := fixtureWitnesses()
	rows[0].FileID = sql.NullString{}
	rows[0].StartOffset = sql.NullInt64{}
	rows[0].EndOffset = sql.NullInt64{}
	rows[0].FinalizedAt = sql.NullTime{}
	report := Verify(fixtureManifest(), rows)
	if report.WitnessConfirmed || !hasIssue(report, "legacy_or_missing_position") || !hasIssue(report, "lane_not_finalized") {
		t.Fatalf("legacy row accepted: %+v", report)
	}
	rows = fixtureWitnesses()
	rows[1].FinalizedAt = sql.NullTime{}
	report = Verify(fixtureManifest(), rows)
	if report.WitnessConfirmed || !hasIssue(report, "lane_not_finalized") {
		t.Fatalf("unfinished lane accepted: %+v", report)
	}
}

func TestWitnessAuditRejectsMissingAndConflictingRows(t *testing.T) {
	rows := fixtureWitnesses()
	rows[0].Found = false
	rows[1].ProjectionSHA256 = strings.Repeat("e", 64)
	rows[1].EventCount++
	report := Verify(fixtureManifest(), rows)
	for _, code := range []string{"segment_missing", "projection_hash_mismatch", "event_count_mismatch"} {
		if !hasIssue(report, code) {
			t.Fatalf("%s missing: %+v", code, report)
		}
	}
	if report.WitnessConfirmed || report.CleanupAllowed {
		t.Fatalf("conflicts accepted: %+v", report)
	}
}

func TestWitnessAuditRejectsMalformedAndDuplicateManifest(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Segments[1].ID = manifest.Segments[0].ID
	report := Verify(manifest, fixtureWitnesses())
	if report.WitnessConfirmed || !hasIssue(report, "duplicate_segment_id") {
		t.Fatalf("duplicate accepted: %+v", report)
	}
	manifest = fixtureManifest()
	manifest.Segments[0].ProjectionSHA256 = "not-a-hash"
	report = Verify(manifest, fixtureWitnesses())
	if report.WitnessConfirmed || !hasIssue(report, "invalid_projection_hash") {
		t.Fatalf("bad hash accepted: %+v", report)
	}
}

func hasIssue(report Report, code string) bool {
	for _, issue := range report.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
