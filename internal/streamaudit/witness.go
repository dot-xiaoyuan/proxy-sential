// Package streamaudit checks a bounded, independently recorded source interval
// against PostgreSQL's projection finalization witnesses. Passing this check
// is only one prerequisite for archival coverage; it never authorizes cleanup.
package streamaudit

import (
	"database/sql"
	"encoding/hex"
	"time"
)

const MaxSegments = 128

type ExpectedSegment struct {
	ID               string `json:"segment_id"`
	ProjectionSHA256 string `json:"projection_sha256"`
	EventCount       int    `json:"event_count"`
	StartOffset      int64  `json:"start_offset"`
	EndOffset        int64  `json:"end_offset"`
}

// Manifest must come from an independently retained, immutable source record.
// PostgreSQL rows alone cannot establish that this list omits no segments.
type Manifest struct {
	Epoch       string            `json:"epoch"`
	SourceKind  string            `json:"source_kind"`
	SourcePath  string            `json:"source_path"`
	FileID      string            `json:"file_id"`
	StartOffset int64             `json:"start_offset"`
	EndOffset   int64             `json:"end_offset"`
	Segments    []ExpectedSegment `json:"segments"`
}

type Witness struct {
	Found            bool
	ID               string
	Epoch            string
	SourceKind       string
	SourcePath       string
	FileID           sql.NullString
	StartOffset      sql.NullInt64
	EndOffset        sql.NullInt64
	ProjectionSHA256 string
	EventCount       int
	ProjectedAt      time.Time
	FinalizedAt      sql.NullTime
}

type Issue struct {
	Code      string `json:"code"`
	SegmentID string `json:"segment_id,omitempty"`
}

type Report struct {
	Epoch                string  `json:"epoch"`
	SourceKind           string  `json:"source_kind"`
	SourcePath           string  `json:"source_path"`
	FileID               string  `json:"file_id"`
	StartOffset          int64   `json:"start_offset"`
	EndOffset            int64   `json:"end_offset"`
	SegmentCount         int     `json:"segment_count"`
	ProjectedEventCount  int     `json:"projected_event_count"`
	WitnessConfirmed     bool    `json:"witness_confirmed"`
	ManifestCompleteness string  `json:"manifest_completeness"`
	ReceiptCoverage      string  `json:"receipt_coverage"`
	BodyCoverage         string  `json:"body_coverage"`
	SourceRawCoverage    string  `json:"source_raw_coverage"`
	ArchiveCoverage      string  `json:"archive_coverage"`
	LateReplayCoverage   string  `json:"late_replay_coverage"`
	CaseProtection       string  `json:"case_protection"`
	CleanupAllowed       bool    `json:"cleanup_allowed"`
	Issues               []Issue `json:"issues"`
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ManifestIssues checks only the bounded input and its claimed interval.
// A valid manifest is not proof that no source segment was omitted.
func ManifestIssues(manifest Manifest) []Issue {
	issues := []Issue{}
	add := func(code, id string) { issues = append(issues, Issue{Code: code, SegmentID: id}) }
	if manifest.Epoch == "" || manifest.SourceKind == "" || manifest.SourcePath == "" || manifest.FileID == "" ||
		manifest.StartOffset < 0 || manifest.EndOffset <= manifest.StartOffset || len(manifest.Segments) == 0 || len(manifest.Segments) > MaxSegments {
		add("invalid_manifest_bounds", "")
	}
	expected := make(map[string]struct{}, len(manifest.Segments))
	next := manifest.StartOffset
	for _, segment := range manifest.Segments {
		if !validSHA256(segment.ID) {
			add("invalid_segment_id", segment.ID)
		}
		if !validSHA256(segment.ProjectionSHA256) {
			add("invalid_projection_hash", segment.ID)
		}
		if segment.EventCount <= 0 || segment.EventCount > 1000 {
			add("invalid_event_count", segment.ID)
		}
		if segment.StartOffset != next || segment.EndOffset <= segment.StartOffset {
			add("manifest_position_gap_or_overlap", segment.ID)
		}
		next = segment.EndOffset
		if _, duplicate := expected[segment.ID]; duplicate {
			add("duplicate_segment_id", segment.ID)
		}
		expected[segment.ID] = struct{}{}
	}
	if next != manifest.EndOffset {
		add("manifest_end_mismatch", "")
	}
	return issues
}

// Verify checks exactly the listed segments, including a continuous order
// within the supplied interval. It deliberately cannot infer source sealing,
// event receipts, ClickHouse retention or protected case references.
func Verify(manifest Manifest, witnesses []Witness) Report {
	report := Report{
		Epoch: manifest.Epoch, SourceKind: manifest.SourceKind, SourcePath: manifest.SourcePath,
		FileID: manifest.FileID, StartOffset: manifest.StartOffset, EndOffset: manifest.EndOffset,
		SegmentCount: len(manifest.Segments), ManifestCompleteness: "unverified",
		ReceiptCoverage: "unverified", BodyCoverage: "unverified", SourceRawCoverage: "unverified",
		ArchiveCoverage: "unverified", LateReplayCoverage: "unverified", CaseProtection: "unverified",
		Issues: []Issue{},
	}
	add := func(code, id string) { report.Issues = append(report.Issues, Issue{Code: code, SegmentID: id}) }
	report.Issues = append(report.Issues, ManifestIssues(manifest)...)
	expected := make(map[string]ExpectedSegment, len(manifest.Segments))
	for _, segment := range manifest.Segments {
		report.ProjectedEventCount += segment.EventCount
		expected[segment.ID] = segment
	}
	actual := make(map[string]Witness, len(witnesses))
	for _, row := range witnesses {
		if _, duplicate := actual[row.ID]; duplicate {
			add("duplicate_witness_row", row.ID)
		}
		if _, listed := expected[row.ID]; !listed {
			add("unexpected_witness_row", row.ID)
		}
		actual[row.ID] = row
	}
	for _, segment := range manifest.Segments {
		row, listed := actual[segment.ID]
		if !listed || !row.Found {
			add("segment_missing", segment.ID)
			continue
		}
		if row.Epoch != manifest.Epoch || row.SourceKind != manifest.SourceKind || row.SourcePath != manifest.SourcePath {
			add("source_identity_mismatch", segment.ID)
		}
		if !row.FileID.Valid || !row.StartOffset.Valid || !row.EndOffset.Valid || row.FileID.String == "" {
			add("legacy_or_missing_position", segment.ID)
		} else if row.FileID.String != manifest.FileID || row.StartOffset.Int64 != segment.StartOffset || row.EndOffset.Int64 != segment.EndOffset {
			add("source_position_mismatch", segment.ID)
		}
		if row.ProjectionSHA256 != segment.ProjectionSHA256 {
			add("projection_hash_mismatch", segment.ID)
		}
		if row.EventCount != segment.EventCount {
			add("event_count_mismatch", segment.ID)
		}
		if !row.FinalizedAt.Valid {
			add("lane_not_finalized", segment.ID)
		} else if row.FinalizedAt.Time.Before(row.ProjectedAt) {
			add("finalization_before_projection", segment.ID)
		}
	}
	report.WitnessConfirmed = len(report.Issues) == 0
	return report
}
