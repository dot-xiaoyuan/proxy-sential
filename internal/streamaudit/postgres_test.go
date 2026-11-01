package streamaudit

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAuditPostgresReadsOnlyExactSegmentIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manifest := fixtureManifest()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	columns := []string{"segment_id", "epoch", "source_kind", "source_path", "source_file_id", "source_start_offset", "source_end_offset", "content_sha256", "event_count", "projected_at", "lanes_finalized_at"}
	projected := time.Now().Add(-time.Second)
	for _, segment := range manifest.Segments {
		mock.ExpectQuery("FROM stream_projection_segments WHERE segment_id=\\$1 LIMIT 1").
			WithArgs(segment.ID).
			WillReturnRows(sqlmock.NewRows(columns).AddRow(segment.ID, manifest.Epoch, manifest.SourceKind, manifest.SourcePath,
				manifest.FileID, segment.StartOffset, segment.EndOffset, segment.ProjectionSHA256, segment.EventCount, projected, time.Now()))
	}
	mock.ExpectRollback()
	report, err := AuditPostgres(context.Background(), db, manifest)
	if err != nil || !report.WitnessConfirmed || report.CleanupAllowed {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditPostgresRefusesInvalidManifestBeforeOpeningTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manifest := fixtureManifest()
	manifest.Segments[1].StartOffset++
	report, err := AuditPostgres(context.Background(), db, manifest)
	if err != nil || report.WitnessConfirmed || !hasIssue(report, "manifest_position_gap_or_overlap") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
