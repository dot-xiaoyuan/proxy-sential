package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStream3ArchiveConfirmationUsesSegmentAndManifestProof(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	segment.AcceptedAt = segment.AcceptedAt.Add(123456789 * time.Nanosecond)
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	scope, hashes, err := stream3ScopeAndHashes(prepared)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT content_sha256,passive_key_scheme FROM stream_projection_segments").WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "passive_key_scheme"}).AddRow(streamProjectionSegmentHash(segment, prepared), "stream3"))
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).
		WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, segment.Epoch, segment.Source, segment.SourcePath, "manifest", "stream3", int64(0), 1, segment.AcceptedAt.Truncate(time.Microsecond), segment.AcceptedAt.Truncate(time.Microsecond),
			nil, segment.FileID, segment.StartOffset, segment.EndOffset, segment.ArchiveMonth, segment.BodyLayout, "stream3", scope, hashes, []byte(`["applied"]`)))
	expectNoStream3Diagnostics(mock)
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), id, segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStream3ProjectionWritesManifestWithoutEventKeyLedger(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	segment.Events[0].Timestamp = "invalid-observation-time"
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].HasFact {
		t.Fatalf("fixture should have only a rejected receipt: %+v %v", prepared, err)
	}
	scope, hashes, err := stream3ScopeAndHashes(prepared)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("(?s)INSERT INTO stream_projection_segments.*passive_key_scheme,source_generation").
		WithArgs(id, segment.Epoch, segment.Source, segment.SourcePath, streamProjectionSegmentHash(segment, prepared),
			segment.AcceptedAt, 1, segment.FileID, segment.StartOffset, segment.EndOffset, "manifest", int64(0)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("recognition-fresh-cutoff").WillReturnRows(sqlmock.NewRows([]string{"since"}))
	mock.ExpectExec("(?s)INSERT INTO stream_discovery_segment_receipt_manifests.*key_scheme,scope_id,content_hashes").
		WithArgs(id, segment.ArchiveMonth, segment.BodyLayout, sqlmock.AnyArg(), sqlmock.AnyArg(), scope, hashes).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), id, segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStream3RecoveryReusesCommittedMarkerWithWriterFlagsOff(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("(?s)INSERT INTO stream_projection_segments.*passive_key_scheme,source_generation").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT content_sha256,passive_key_scheme,source_generation FROM stream_projection_segments").WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "passive_key_scheme", "source_generation"}).
			AddRow(streamProjectionSegmentHash(segment, prepared), "stream3", int64(0)))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), id, segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
