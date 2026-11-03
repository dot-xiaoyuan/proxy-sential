package discovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

var stream3ReceiptColumns = []string{"segment_id", "epoch", "source_kind", "source_path", "archive_receipt_mode", "passive_key_scheme", "source_generation", "event_count", "accepted_at", "projected_at", "lanes_finalized_at", "source_file_id", "source_start_offset", "source_end_offset", "archive_month", "body_layout", "key_scheme", "scope_id", "content_hashes", "results"}
var stream3DiagnosticColumns = []string{"event_key", "content_sha256", "accepted_at", "result", "body_ref", "archive_state", "archive_segment_id"}

func expectNoStream3Diagnostics(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("(?s)FROM jsonb_to_recordset.*JOIN stream_discovery_receipts").
		WillReturnRows(sqlmock.NewRows(stream3DiagnosticColumns))
}

func stream3ReceiptTestID() string {
	return streamlog.SourceSegmentID(streamlog.Segment{Epoch: "fresh-1", Source: "passive-discovery", SourcePath: "packet://test", FileID: "capture-a", StartOffset: 0, EndOffset: 100})
}

func TestStream3ReceiptReadsOneManifestForMultipleOrdinals(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := stream3ReceiptTestID()
	keys := []string{"fresh-1:stream3-" + id + "-1", "fresh-1:stream3-" + id + "-0"}
	accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	projected := accepted.Add(time.Second)
	hashes := append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)...)
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).
		WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, "fresh-1", "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 2, accepted, projected, nil, "capture-a", int64(0), int64(100), "202611", "", "stream3", "scope-a", hashes, []byte(`["applied","repeat_observation"]`)))
	expectNoStream3Diagnostics(mock)
	items, missing, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), "fresh-1", "scope-a", keys)
	if err != nil || len(missing) != 0 || len(items) != 2 || items[0]["event_key"] != keys[0] || items[0]["result"] != "repeat_observation" || items[0]["content_sha256"] != hex.EncodeToString(hashes[32:]) || items[0]["archive_state"] != "pending" || items[1]["event_key"] != keys[1] || items[1]["result"] != "applied" {
		t.Fatalf("stream3 batch: items=%+v missing=%+v err=%v", items, missing, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStream3ReceiptRejectsMissingOrCorruptManifest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   any
		hashes  any
		results any
		end     int64
		want    error
	}{
		{"missing", nil, nil, nil, 100, streamlog.ErrUnconfirmed},
		{"short_hashes", "scope-a", bytes.Repeat([]byte{0x11}, 31), []byte(`["applied"]`), 100, streamlog.ErrContentConflict},
		{"empty_result", "scope-a", bytes.Repeat([]byte{0x11}, 32), []byte(`[""]`), 100, streamlog.ErrContentConflict},
		{"wrong_source_position", "scope-a", bytes.Repeat([]byte{0x11}, 32), []byte(`["applied"]`), 101, streamlog.ErrContentConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id := stream3ReceiptTestID()
			key := "fresh-1:stream3-" + id + "-0"
			accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
			var scheme, month, layout any = "stream3", "202611", ""
			if tc.scope == nil {
				scheme, month, layout = nil, nil, nil
			}
			mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
				WithArgs([]byte(`["` + id + `"]`)).
				WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, "fresh-1", "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 1, accepted, accepted, nil, "capture-a", int64(0), tc.end, month, layout, scheme, tc.scope, tc.hashes, tc.results))
			_, _, err = (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got error %v, want %v", err, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStream3ReceiptDoesNotInventAbsentSegment(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := strings.Repeat("c", 64)
	key := "fresh-1:stream3-" + id + "-0"
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns))
	_, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
	if err != nil || found {
		t.Fatalf("absent segment: found=%v err=%v", found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStream3ReceiptRejectsExistingMarkerWithDifferentIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, epoch, scheme string
	}{
		{"wrong_epoch", "other-epoch", "stream3"},
		{"legacy_scheme", "fresh-1", "legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id := stream3ReceiptTestID()
			accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
			mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
				WithArgs([]byte(`["` + id + `"]`)).
				WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, tc.epoch, "passive-discovery", "packet://test", "manifest", tc.scheme, int64(0), 1, accepted, accepted, nil,
					"capture-a", int64(0), int64(100), "202611", "", "stream3", "scope-a", bytes.Repeat([]byte{0x11}, 32), []byte(`["applied"]`)))
			_, _, err = (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", "fresh-1:stream3-"+id+"-0")
			if !errors.Is(err, streamlog.ErrContentConflict) {
				t.Fatalf("existing conflicting marker returned %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStream3ReceiptRejectsMalformedKeyWithoutDatabaseLookup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := "fresh-1:stream3-" + strings.Repeat("a", 64) + "-00"
	_, _, err = (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
	if err == nil {
		t.Fatal("noncanonical stream3 key accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStream3ReceiptRequiresFinalizationForConfirmedState(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := stream3ReceiptTestID()
	key := "fresh-1:stream3-" + id + "-0"
	accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	finalized := accepted.Add(2 * time.Second)
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).
		WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, "fresh-1", "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 1, accepted, accepted.Add(time.Second), finalized, "capture-a", int64(0), int64(100), "202611", "v2", "stream3", "scope-a", bytes.Repeat([]byte{0x11}, 32), []byte(`["applied"]`)))
	expectNoStream3Diagnostics(mock)
	receipt, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
	if err != nil || !found || receipt["archive_state"] != "confirmed" {
		t.Fatalf("finalized stream3 receipt: %+v found=%v err=%v", receipt, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStream3ReceiptChecksOptionalDiagnosticAgainstManifest(t *testing.T) {
	for _, tc := range []struct {
		name, state, result, hash, refHash, locator string
		acceptanceOffset                            time.Duration
		want                                        error
	}{
		{"matching", "segment", "applied", strings.Repeat("11", 32), strings.Repeat("11", 32), "same", 0, nil},
		{"rounded_microsecond", "segment", "applied", strings.Repeat("11", 32), strings.Repeat("11", 32), "same", time.Microsecond, nil},
		{"failed", "failed", "applied", strings.Repeat("11", 32), strings.Repeat("11", 32), "same", 0, streamlog.ErrUnconfirmed},
		{"wrong_hash", "segment", "applied", strings.Repeat("22", 32), strings.Repeat("11", 32), "same", 0, streamlog.ErrContentConflict},
		{"wrong_ref", "segment", "applied", strings.Repeat("11", 32), strings.Repeat("22", 32), "same", 0, streamlog.ErrContentConflict},
		{"wrong_result", "segment", "changed", strings.Repeat("11", 32), strings.Repeat("11", 32), "same", 0, streamlog.ErrContentConflict},
		{"wrong_locator", "segment", "applied", strings.Repeat("11", 32), strings.Repeat("11", 32), "wrong", 0, streamlog.ErrContentConflict},
		{"wrong_acceptance", "segment", "applied", strings.Repeat("11", 32), strings.Repeat("11", 32), "same", 2 * time.Microsecond, streamlog.ErrContentConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id := stream3ReceiptTestID()
			key := "fresh-1:stream3-" + id + "-0"
			accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
			mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
				WithArgs([]byte(`["` + id + `"]`)).
				WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, "fresh-1", "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 1, accepted, accepted, accepted.Add(time.Second),
					"capture-a", int64(0), int64(100), "202611", "", "stream3", "scope-a", bytes.Repeat([]byte{0x11}, 32), []byte(`["applied"]`)))
			locator := id
			if tc.locator == "wrong" {
				locator = strings.Repeat("0", 64)
			}
			ref := []byte(`{"class":"evidence","epoch":"fresh-1","key":"` + key + `","month":"202611","scope":"scope-a","sha256":"` + tc.refHash + `"}`)
			mock.ExpectQuery("(?s)FROM jsonb_to_recordset.*JOIN stream_discovery_receipts").
				WithArgs("fresh-1", "scope-a", []byte(`[{"event_key":"`+key+`","archive_month":"202611"}]`)).
				WillReturnRows(sqlmock.NewRows(stream3DiagnosticColumns).AddRow(key, tc.hash, accepted.Add(tc.acceptanceOffset), tc.result, ref, tc.state, locator))
			receipt, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("conflicting diagnostic returned %v, want %v", err, tc.want)
				}
			} else if err != nil || !found || receipt["archive_state"] != "confirmed" {
				t.Fatalf("matching diagnostic: receipt=%+v found=%v err=%v", receipt, found, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStream3ReceiptRejectsAnotherMissingResultInSameManifest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := stream3ReceiptTestID()
	key := "fresh-1:stream3-" + id + "-0"
	accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).
		WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, "fresh-1", "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 2, accepted, accepted, nil, "capture-a", int64(0), int64(100), "202611", "", "stream3", "scope-a", bytes.Repeat([]byte{0x11}, 64), []byte(`["applied",null]`)))
	_, _, err = (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("partial manifest accepted: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
