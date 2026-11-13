package discovery

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func stream4TestSegment() (string, streamlog.Segment) {
	s := finalizationWitnessSegment()
	s.Source = "device-signals"
	s.SourcePath = "/signals/device.jsonl"
	s.RawIsStandardEvents = true
	s.Events = append([]normalized.Event(nil), s.Events...)
	s.Events = append([]normalized.Event{{SchemaVersion: "v1", EventID: "stream-archive-only", Type: "device", SourceEventType: "ttl", Timestamp: s.Events[0].Timestamp}}, s.Events...)
	id := streamlog.SourceSegmentID(s)
	s.Events[1].EventID = fmt.Sprintf("stream4-%s-0", id)
	return id, s
}

func TestDeviceStream4KeyCanonicalParser(t *testing.T) {
	id, _ := stream4TestSegment()
	good := "fresh:stream4-" + id + "-0"
	if got, ordinal, ok := ParseDeviceStream4Key("fresh", good); !ok || got != id || ordinal != 0 {
		t.Fatalf("valid locator rejected: %s %d %v", got, ordinal, ok)
	}
	if got, ordinal, ok := ParseDeviceStream4Key("fresh", "fresh:stream4-"+id+"-999"); !ok || got != id || ordinal != 999 {
		t.Fatal("last valid device ordinal rejected")
	}
	for _, key := range []string{"fresh:stream4-" + id + "-00", "fresh:stream4-" + strings.ToUpper(id) + "-0", "fresh:stream4-" + id + "-1000", "wrong:stream4-" + id + "-0", "fresh:stream4-" + id + "--1"} {
		if _, _, ok := ParseDeviceStream4Key("fresh", key); ok {
			t.Fatalf("noncanonical locator accepted: %s", key)
		}
	}
}

func TestDeviceStream4MixedSegmentUsesOnlyProjectionOrdinals(t *testing.T) {
	id, segment := stream4TestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 {
		t.Fatalf("projection subset: %d %v", len(prepared), err)
	}
	if err := verifyStream4PreparedSegment(id, segment, prepared); err != nil {
		t.Fatalf("valid mixed segment: %v", err)
	}
	segment.Events[1].EventID = "stream4-" + id + "-1"
	prepared, _ = prepareStreamDiscovery(segment)
	if !errors.Is(verifyStream4PreparedSegment(id, segment, prepared), streamlog.ErrContentConflict) {
		t.Fatal("shifted projection ordinal accepted")
	}
}

func TestDeviceStream4ReceiptReadsSegmentProofWithoutKeyRows(t *testing.T) {
	id, segment := stream4TestSegment()
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
	key := segment.Epoch + ":" + segment.Events[1].EventID
	accepted := segment.AcceptedAt.Truncate(time.Microsecond)
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).
		WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, segment.Epoch, segment.Source, segment.SourcePath, "manifest", "stream4", int64(segment.SourceGeneration), 1, accepted, accepted, accepted.Add(time.Second), segment.FileID, segment.StartOffset, segment.EndOffset, segment.ArchiveMonth, segment.BodyLayout, "stream4", scope, hashes, []byte(`["applied"]`)))
	expectNoStream3Diagnostics(mock)
	mock.ExpectQuery("(?s)SELECT EXISTS\\(.*stream_discovery_event_keys k.*stream_discovery_event_keys_compact k").
		WithArgs(segment.Epoch, scope, []byte(`["`+key+`"]`)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	receipt, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), segment.Epoch, scope, key)
	if err != nil || !found || receipt["content_sha256"] != prepared[0].Receipt.Hash || receipt["archive_state"] != "confirmed" {
		t.Fatalf("keyless receipt: %v found=%v err=%v", receipt, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceStream4BatchAndConflictingLegacyKey(t *testing.T) {
	id, segment := stream4TestSegment()
	second := segment.Events[1]
	second.EventID = "stream4-" + id + "-1"
	segment.Events = append(segment.Events, second)
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || verifyStream4PreparedSegment(id, segment, prepared) != nil {
		t.Fatalf("two projection receipts: %v", err)
	}
	scope, hashes, err := stream3ScopeAndHashes(prepared)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{prepared[1].Receipt.Key, prepared[0].Receipt.Key}
	for _, conflict := range []bool{false, true} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		accepted := segment.AcceptedAt.Truncate(time.Microsecond)
		mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
			WithArgs([]byte(`["` + id + `"]`)).
			WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, segment.Epoch, segment.Source, segment.SourcePath, "manifest", "stream4", int64(0), 2, accepted, accepted, nil, segment.FileID, segment.StartOffset, segment.EndOffset, segment.ArchiveMonth, "", "stream4", scope, hashes, []byte(`["applied","repeat_observation"]`)))
		expectNoStream3Diagnostics(mock)
		// The conflict probe is bounded by the two requested keys, not by
		// the segment's complete event count.
		mock.ExpectQuery("(?s)SELECT EXISTS\\(.*stream_discovery_event_keys k.*stream_discovery_event_keys_compact k").
			WithArgs(segment.Epoch, scope, sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(conflict))
		items, missing, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), segment.Epoch, scope, keys)
		if conflict {
			if !errors.Is(err, streamlog.ErrContentConflict) {
				t.Fatalf("legacy collision accepted: %v", err)
			}
		} else if err != nil || len(missing) != 0 || len(items) != 2 || items[0]["content_sha256"] != hex.EncodeToString(hashes[32:]) || items[1]["result"] != "applied" {
			t.Fatalf("batch receipts: %+v missing=%+v err=%v", items, missing, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}

func TestDeviceStream4ProjectionWritesOneManifestWithoutKeyRows(t *testing.T) {
	id, segment := stream4TestSegment()
	segment.Events[1].Timestamp = "invalid-observation-time"
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].HasFact {
		t.Fatalf("rejected fixture: %+v %v", prepared, err)
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
		WithArgs(id, segment.Epoch, segment.Source, segment.SourcePath, streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, 1, segment.FileID, segment.StartOffset, segment.EndOffset, "manifest", int64(segment.SourceGeneration)).
		WillReturnResult(sqlmock.NewResult(0, 1))
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

func TestDeviceStream4ProjectionRecoveryKeepsCommittedMarkerWithWriterOff(t *testing.T) {
	id, segment := stream4TestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, hash, scheme string
		wantErr            bool
	}{
		{"same", streamProjectionSegmentHash(segment, prepared), "stream4", false},
		{"changed_hash", "different", "stream4", true},
		{"changed_scheme", streamProjectionSegmentHash(segment, prepared), "legacy", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec("(?s)INSERT INTO stream_projection_segments.*passive_key_scheme,source_generation").
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("SELECT content_sha256,passive_key_scheme,source_generation FROM stream_projection_segments").WithArgs(id).
				WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "passive_key_scheme", "source_generation"}).AddRow(tc.hash, tc.scheme, int64(0)))
			if tc.wantErr {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			err = (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), id, segment)
			if tc.wantErr && !errors.Is(err, streamlog.ErrContentConflict) || !tc.wantErr && err != nil {
				t.Fatalf("recovery error=%v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeviceStream4ManifestFailureRollsBackWholeProjection(t *testing.T) {
	id, segment := stream4TestSegment()
	segment.Events[1].Timestamp = "invalid-observation-time"
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_discovery_segment_receipt_manifests").WillReturnError(errors.New("disk write interrupted"))
	mock.ExpectRollback()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), id, segment); err == nil {
		t.Fatal("failed manifest committed marker without receipts")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceStream4ArchiveConfirmationChecksManifest(t *testing.T) {
	id, segment := stream4TestSegment()
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
		WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "passive_key_scheme"}).AddRow(streamProjectionSegmentHash(segment, prepared), "stream4"))
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).
		WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, segment.Epoch, segment.Source, segment.SourcePath, "manifest", "stream4", int64(segment.SourceGeneration), 1, segment.AcceptedAt.Truncate(time.Microsecond), segment.AcceptedAt.Truncate(time.Microsecond), nil, segment.FileID, segment.StartOffset, segment.EndOffset, segment.ArchiveMonth, segment.BodyLayout, "stream4", scope, hashes, []byte(`["applied"]`)))
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), id, segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceStream4RejectedWhenSourceWitnessChanges(t *testing.T) {
	id, segment := stream4TestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	segment.EndOffset++
	if !errors.Is(verifyStream4PreparedSegment(id, segment, prepared), streamlog.ErrContentConflict) {
		t.Fatal("source interval substitution accepted")
	}
}
