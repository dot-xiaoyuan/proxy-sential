package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

func TestStreamProjectionPolicyLegacyFingerprint(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	hash := streamProjectionSegmentHash(segment, prepared)
	if hash != "14c73afe6a0d08db5f4f0e9bcef40c24347777b6b5c2c6ec4cb8bafa8c4ecf1c" ||
		id != "ed913510669f305e2d1aae064ed79d9f34ee02cd26fd15f1ea34a2ebcae6f429" {
		t.Fatalf("legacy projection fingerprint changed: hash=%s segment=%s", hash, id)
	}
	segment.ProjectionPolicy = streamlog.ProjectionPolicyFull
	if updated := streamProjectionSegmentHash(segment, prepared); updated == hash || streamlog.SourceSegmentID(segment) != id {
		t.Fatalf("explicit policy must bind projection marker without changing source ID: %s", updated)
	}
}

func TestStreamProjectionPolicyRejectsChangedMarker(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := streamProjectionSegmentHash(segment, prepared)
	segment.ProjectionPolicy = streamlog.ProjectionPolicyFull
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT content_sha256,passive_key_scheme,source_generation FROM stream_projection_segments").WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "passive_key_scheme", "source_generation"}).AddRow(legacyHash, "stream3", int64(0)))
	mock.ExpectRollback()
	err = (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), id, segment)
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("changed policy accepted against durable marker: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedOnlyProjectionCannotBeAcknowledgedBeforeImplementation(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	segment.ProjectionPolicy = streamlog.ProjectionPolicySharedOnly
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	projector := StreamDiscoveryProjector{DB: db}
	for _, run := range []func() error{
		func() error { return projector.ProjectStreamSegment(context.Background(), id, segment) },
		func() error { return projector.ReconcileStreamProjection(context.Background(), id, segment) },
		func() error { return projector.MarkStreamArchiveConfirmed(context.Background(), id, segment) },
		func() error { return projector.MarkStreamSegmentFinalized(context.Background(), id, segment) },
	} {
		if err := run(); !errors.Is(err, ErrUnsupportedStreamProjection) {
			t.Fatalf("shared-only segment was acknowledged without a projection: %v", err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
