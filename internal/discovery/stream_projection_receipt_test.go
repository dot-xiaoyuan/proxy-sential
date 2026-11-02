package discovery

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func receiptPreparationSegment(count int) streamlog.Segment {
	events := make([]normalized.Event, count)
	for i := range events {
		events[i] = streamDiscoveryEvent(fmt.Sprintf("event-%04d", i), "2026-11-01T08:00:00Z", 600)
		events[i].Payload["service_instance"] = fmt.Sprintf("printer-%04d", i)
	}
	return streamlog.Segment{Epoch: "receipt-replay", Source: "passive-discovery", SourcePath: "packet://bond0/passive-sensor-a", ArchiveMonth: "202611", AcceptedAt: time.Date(2026, 11, 1, 8, 0, 1, 0, time.UTC), Events: events}
}

func TestStreamArchiveConfirmationRetainsRejectedAndOutsideScopeReceipts(t *testing.T) {
	segment := receiptPreparationSegment(4)
	segment.Events[0].Timestamp = "invalid-observation-time"
	segment.Events[1].Subject["ip"] = "203.0.113.4"
	segment.Events[2].Payload["ttl"] = 0
	segment.Events[3].Payload["revision"] = 2
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].HasFact || items[0].Receipt.Result == "applied" || items[1].Receipt.Result != "outside_private_scope" {
		t.Fatalf("fixture lacks rejected or outside-scope receipts: %+v", items)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want := make(streamArchiveKeys, len(items))
	for i, item := range items {
		want[i] = item.Receipt
	}
	mock.ExpectBegin()
	mock.ExpectQuery("WITH input AS MATERIALIZED").WithArgs(segment.Epoch, want).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(len(want)))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "segment", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamArchiveConfirmationUsesCompactLedgerForStream2(t *testing.T) {
	segment := receiptPreparationSegment(1)
	segment.Events[0].EventID = "stream2-source-position"
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT archive_receipt_mode,epoch,source_kind").WithArgs("segment").WillReturnRows(
		sqlmock.NewRows([]string{"archive_receipt_mode", "epoch", "source_kind", "source_path", "content_sha256", "source_file_id", "source_start_offset", "source_end_offset", "event_count"}).
			AddRow("event", segment.Epoch, segment.Source, segment.SourcePath, "", nil, nil, nil, len(items)))
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_event_keys_compact k").WithArgs(segment.Epoch, streamArchiveKeys{items[0].Receipt}).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "segment", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamArchiveConfirmationUsesPersistedSegmentWitness(t *testing.T) {
	segment := finalizationWitnessSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name string
		hash string
		want error
	}{
		{"matching segment", streamProjectionSegmentHash(segment, prepared), nil},
		{"different segment body", "wrong-hash", streamlog.ErrContentConflict},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("SELECT archive_receipt_mode,epoch,source_kind").WithArgs("segment-a").WillReturnRows(
				sqlmock.NewRows([]string{"archive_receipt_mode", "epoch", "source_kind", "source_path", "content_sha256", "source_file_id", "source_start_offset", "source_end_offset", "event_count"}).
					AddRow("segment", segment.Epoch, segment.Source, segment.SourcePath, scenario.hash,
						segment.FileID, segment.StartOffset, segment.EndOffset, len(prepared)))
			err = (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "segment-a", segment)
			if !errors.Is(err, scenario.want) || scenario.want == nil && err != nil {
				t.Fatalf("archive witness admission: %v, want %v", err, scenario.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManifestArchiveConfirmationSurvivesWriterRollback(t *testing.T) {
	segment := finalizationWitnessSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	for _, matched := range []int{0, len(prepared)} {
		t.Run(fmt.Sprint(matched), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("SELECT archive_receipt_mode,epoch,source_kind").WithArgs("segment-a").WillReturnRows(
				sqlmock.NewRows([]string{"archive_receipt_mode", "epoch", "source_kind", "source_path", "content_sha256", "source_file_id", "source_start_offset", "source_end_offset", "event_count"}).
					AddRow("manifest", segment.Epoch, segment.Source, segment.SourcePath, streamProjectionSegmentHash(segment, prepared),
						segment.FileID, segment.StartOffset, segment.EndOffset, len(prepared)))
			mock.ExpectQuery("FROM stream_discovery_segment_receipt_manifests m").
				WithArgs("segment-a", segment.Epoch, sqlmock.AnyArg(), streamAcceptedMonth(segment.AcceptedAt)).
				WillReturnRows(sqlmock.NewRows([]string{"archive_month", "body_layout", "results", "matched"}).
					AddRow(segment.ArchiveMonth, segment.BodyLayout, len(prepared), matched))
			err = (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "segment-a", segment)
			if matched == len(prepared) && err != nil || matched == 0 && !errors.Is(err, streamlog.ErrContentConflict) {
				t.Fatalf("manifest finalizer result: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSegmentWitnessIncludesRejectedReceiptResult(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Events[0].Timestamp = "invalid-observation-time"
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].HasFact {
		t.Fatalf("expected rejected receipt: %+v %v", prepared, err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT archive_receipt_mode,epoch,source_kind").WithArgs("segment-a").WillReturnRows(
		sqlmock.NewRows([]string{"archive_receipt_mode", "epoch", "source_kind", "source_path", "content_sha256", "source_file_id", "source_start_offset", "source_end_offset", "event_count"}).
			AddRow("segment", segment.Epoch, segment.Source, segment.SourcePath, streamProjectionSegmentHash(segment, prepared),
				segment.FileID, segment.StartOffset, segment.EndOffset, len(prepared)))
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestNonPassiveLegacyStream2SegmentCanStillRecover(t *testing.T) {
	segment := receiptPreparationSegment(1)
	segment.Source = "device-signals"
	segment.Events[0].EventID = "stream2-old-source"
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 {
		t.Fatalf("legacy non-passive projection blocked: %d %v", len(prepared), err)
	}
	receipts, err := prepareStreamArchiveReceipts(segment)
	if err != nil || len(receipts) != 1 || receipts[0].Key != segment.Epoch+":stream2-old-source" {
		t.Fatalf("legacy non-passive confirmation blocked: %+v %v", receipts, err)
	}
}

func TestStreamArchiveConfirmationRejectsInvalidIdentityBeforeTransaction(t *testing.T) {
	for _, kind := range []string{"epoch", "accepted", "empty", "id", "timestamp", "scope", "encoding", "duplicate", "conflict", "mixed_scheme", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			segment := receiptPreparationSegment(1)
			switch kind {
			case "epoch":
				segment.Epoch = ""
			case "accepted":
				segment.AcceptedAt = time.Time{}
			case "empty":
				segment.Events = nil
			case "id":
				segment.Events[0].EventID = ""
			case "timestamp":
				segment.Events[0].Timestamp = ""
			case "scope":
				delete(segment.Events[0].Observer, "capture_scope_id")
			case "encoding":
				segment.Events[0].Payload["invalid"] = math.NaN()
			case "duplicate":
				segment.Events = append(segment.Events, segment.Events[0])
			case "conflict":
				other := streamDiscoveryEvent(segment.Events[0].EventID, segment.Events[0].Timestamp, 0)
				segment.Events = append(segment.Events, other)
			case "mixed_scheme":
				segment.Events = append(segment.Events, streamDiscoveryEvent("stream2-new", segment.Events[0].Timestamp, 600))
			case "unsupported":
				segment.Events[0].Type = "flow"
				segment.Events[0].SourceEventType = "flow"
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			items, expected := prepareStreamDiscovery(segment)
			if expected == nil && len(items) == 0 {
				expected = ErrUnsupportedStreamProjection
			}
			got := (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "segment", segment)
			if expected == nil || got == nil || got.Error() != expected.Error() {
				t.Fatalf("identity rejection changed or reached a transaction: expected=%v got=%v", expected, got)
			}
			if (kind == "duplicate" || kind == "conflict" || kind == "mixed_scheme") && !errors.Is(got, streamlog.ErrContentConflict) {
				t.Fatalf("lost content conflict: %v", got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkPrepareStreamDiscoveryThousand(b *testing.B) {
	segment := receiptPreparationSegment(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := prepareStreamDiscovery(segment); err != nil {
			b.Fatal(err)
		}
	}
}

func TestReceiptPreparationPreservesProjectionDigest(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		segment := receiptPreparationSegment(6)
		if mixed {
			segment.Events[0].Timestamp = "invalid-observation-time"
			segment.Events[1].Subject["ip"] = "203.0.113.4"
			segment.Events[2].Payload["ttl"] = 0
			segment.Events[3].Payload["revision"] = 2
			segment.Events[4].Type = "flow"
			segment.Events[4].SourceEventType = "flow"
		}
		prepared, err := prepareStreamDiscovery(segment)
		if err != nil {
			t.Fatal(err)
		}
		wantPrepared, wantMarker := "5609a1d8d1d7602bed25d5f0f40c6da7d24239b5e52fd7278dfdcee86577bac2", "3dba8a6cf4b211723671ca8dab1effcb4159c13d032877ce4346dc88a2c444e7"
		if mixed {
			wantPrepared, wantMarker = "461b2760ba83f8080ccdf89481da2674da1fc9b0e1eb91038ac05fc257137506", "b53c9c92cbf90ef9e6d1c1352c7f5b0584cbbc1f4a13f97f07c6a634f7fb9f6c"
		}
		if got := contentHash(prepared); got != wantPrepared {
			t.Fatalf("prepared projection changed: mixed=%t got=%s", mixed, got)
		}
		if got := streamProjectionSegmentHash(segment, prepared); got != wantMarker {
			t.Fatalf("existing committed marker hash changed: mixed=%t got=%s", mixed, got)
		}
	}
}

func BenchmarkPrepareStreamArchiveReceiptsThousand(b *testing.B) {
	segment := receiptPreparationSegment(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := prepareStreamArchiveReceipts(segment); err != nil {
			b.Fatal(err)
		}
	}
}
