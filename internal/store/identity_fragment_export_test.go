package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestFreshIdentityExportFinishesIndexedFragmentBeforeNewBody(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	after := time.Date(2026, 10, 29, 5, 11, 29, 0, time.UTC)
	accepted := after.Add(time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery("f.body_state='completed' AND f.search_state<>'completed'").WithArgs("ncu", after).
		WillReturnRows(sqlmock.NewRows([]string{"batch_id", "scope_key", "source", "stream_epoch", "archive_month", "content_sha256", "key_scheme", "first_ordinal", "record_count", "accepted_at", "normalized_events", "body_state", "search_state"}).
			AddRow("batch", "scope", "identity-http", "fresh", "202610", "hash", "source_position_v1", 0, 8, accepted, []byte("[]"), "completed", "pending"))
	mock.ExpectQuery("UPDATE identity_ingest_fragments SET lease_epoch").WithArgs("batch", 0).
		WillReturnRows(sqlmock.NewRows([]string{"lease_epoch"}).AddRow(2))
	mock.ExpectCommit()
	fragment, err := (&PostgresStore{db: db, sensorID: "ncu", identityDerivedAfter: after}).claimIdentityExportFragment(context.Background())
	if err != nil || fragment.BatchID != "batch" || fragment.SearchState != "pending" || fragment.LeaseEpoch != 2 {
		t.Fatalf("fresh search receipt was not prioritized: %+v %v", fragment, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFreshIdentityExportFallsBackToUnfinishedBody(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	after := time.Date(2026, 10, 29, 5, 11, 29, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery("f.body_state='completed' AND f.search_state<>'completed'").WithArgs("ncu", after).
		WillReturnRows(sqlmock.NewRows([]string{"batch_id"}))
	mock.ExpectQuery("ORDER BY b.accepted_at DESC").WithArgs("ncu", after).
		WillReturnRows(sqlmock.NewRows([]string{"batch_id", "scope_key", "source", "stream_epoch", "archive_month", "content_sha256", "key_scheme", "first_ordinal", "record_count", "accepted_at", "normalized_events", "body_state", "search_state"}).
			AddRow("new-batch", "scope", "identity-http", "fresh", "202610", "hash", "source_position_v1", 0, 5, after.Add(time.Hour), []byte("[]"), "pending", "pending"))
	mock.ExpectQuery("UPDATE identity_ingest_fragments SET lease_epoch").WithArgs("new-batch", 0).
		WillReturnRows(sqlmock.NewRows([]string{"lease_epoch"}).AddRow(1))
	mock.ExpectCommit()
	fragment, err := (&PostgresStore{db: db, sensorID: "ncu", identityDerivedAfter: after}).claimIdentityExportFragment(context.Background())
	if err != nil || fragment.BatchID != "new-batch" || fragment.BodyState != "pending" {
		t.Fatalf("fresh body could not be claimed after empty search probe: %+v %v", fragment, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityFragmentSegmentKeepsFixedArchiveIdentity(t *testing.T) {
	accepted := time.Date(2026, time.October, 31, 23, 59, 59, 0, time.UTC)
	event := normalized.Event{EventID: "source-position-1", Type: "identity", Timestamp: accepted.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor"}, Subject: map[string]any{"campus_id": "campus"}, Flow: map[string]any{}, Payload: map[string]any{"access_domain": "domain"}}
	parts, err := splitIdentityInboxFragments([]normalized.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(parts[0].JSON, &payload); err == nil {
		t.Fatal("fragment should be an event array")
	}
	fragment := identityExportFragment{BatchID: "batch", Scope: "scope", Source: "identity-http", Epoch: "identity-fresh-1", Month: "202610", Hash: parts[0].SHA256, KeyScheme: "source_position_v1", First: 0, Count: 1, Accepted: accepted, Payload: parts[0].JSON}
	segment, token, err := identityFragmentSegment(fragment)
	if err != nil {
		t.Fatal(err)
	}
	if segment.ArchiveMonth != "202610" || segment.EndOffset != 1 || segment.KeyScheme != "source_position_v1" || segment.NeedsProjection || len(segment.Events) != 1 || token == "" {
		t.Fatalf("unexpected segment: %+v token=%s", segment, token)
	}
	fragment.Accepted = accepted.Add(2 * time.Hour)
	if _, _, err := identityFragmentSegment(fragment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("cross-month retry changed fixed archive month: %v", err)
	}
	fragment.Accepted = accepted
	fragment.Hash = "different"
	if _, _, err := identityFragmentSegment(fragment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("different content at same fragment key was accepted: %v", err)
	}
}

func TestIdentityFragmentSegmentPreservesRepeatedSourcePositions(t *testing.T) {
	accepted := time.Date(2026, time.October, 24, 15, 0, 0, 0, time.UTC)
	event := normalized.Event{EventID: "same-source-record", Type: "identity", Timestamp: accepted.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor"}, Subject: map[string]any{"campus_id": "campus"}, Payload: map[string]any{"access_domain": "domain"}}
	parts, err := splitIdentityInboxFragments([]normalized.Event{event, event})
	if err != nil {
		t.Fatal(err)
	}
	fragment := identityExportFragment{BatchID: "batch", Scope: "scope", Source: "identity-http", Epoch: "identity-fresh-1", Month: "202610", Hash: parts[0].SHA256, KeyScheme: "source_position_v1", First: 50, Count: 2, Accepted: accepted, Payload: parts[0].JSON}
	segment, _, err := identityFragmentSegment(fragment)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareStreamEvents(segment)
	if err != nil || len(prepared) != 2 || prepared[0].key == prepared[1].key {
		t.Fatalf("repeated records must keep distinct fixed positions: %v %+v", err, prepared)
	}
	fragment.KeyScheme = "event_id_v1"
	if _, _, err := identityFragmentSegment(fragment); !errors.Is(err, ErrInvalidIdentityBatch) {
		t.Fatalf("legacy scheme should expose duplicate event IDs: %v", err)
	}
}
