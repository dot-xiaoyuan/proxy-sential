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

func TestStreamArchiveConfirmationRejectsInvalidIdentityBeforeTransaction(t *testing.T) {
	for _, kind := range []string{"epoch", "accepted", "empty", "id", "timestamp", "scope", "encoding", "duplicate", "conflict", "unsupported"} {
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
			if (kind == "duplicate" || kind == "conflict") && !errors.Is(got, streamlog.ErrContentConflict) {
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
