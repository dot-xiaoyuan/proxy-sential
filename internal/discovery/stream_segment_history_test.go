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

func TestStream3HistoryVerifiesSegmentReceiptAndBodyReference(t *testing.T) {
	for _, tc := range []struct {
		name, refHash string
		archive       any
		legacyPresent bool
		rounded       time.Duration
		wantError     bool
	}{
		{"exact", hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)), nil, false, 0, false},
		{"rounded_microsecond", hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)), nil, false, time.Microsecond, false},
		{"outside_rounding", hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)), nil, false, 2 * time.Microsecond, true},
		{"wrong_hash", strings.Repeat("0", 64), nil, false, 0, true},
		{"legacy_key_cannot_bypass", hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)), "confirmed", true, 0, true},
		{"diagnostic_receipt_is_checked", hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)), "confirmed", false, 0, false},
		{"legacy_status_does_not_bypass", strings.Repeat("0", 64), "confirmed", false, 0, true},
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
			ref := []byte(`{"class":"evidence","epoch":"fresh-1","month":"202611","scope":"scope-a","key":"` + key + `","sha256":"` + tc.refHash + `"}`)
			mock.ExpectQuery(`(?s)CASE WHEN left\(c.event_key.*FROM stream_discovery_changes c`).WithArgs("fresh-1", "device-a", int64(0), 21).
				WillReturnRows(sqlmock.NewRows([]string{"change_id", "event_key", "accepted_at", "observed_at", "change_kind", "before_hash", "after_hash", "body_ref", "archive_state", "legacy_present"}).AddRow(int64(7), key, accepted.Add(tc.rounded), accepted, "applied", "", "after", ref, tc.archive, tc.legacyPresent))
			if !tc.legacyPresent {
				mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
					WithArgs([]byte(`["` + id + `"]`)).
					WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, "fresh-1", "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 1, accepted, accepted, accepted.Add(time.Second), "capture-a", int64(0), int64(100), "202611", "", "stream3", "scope-a", bytes.Repeat([]byte{0x11}, 32), []byte(`["applied"]`)))
				expectNoStream3Diagnostics(mock)
			}
			page, err := (Repository{DB: db}).streamDiscoveryHistory(context.Background(), "fresh-1", "device-a", "", 20)
			if tc.wantError {
				if !errors.Is(err, streamlog.ErrContentConflict) {
					t.Fatalf("wrong history reference accepted: %v", err)
				}
			} else {
				if err != nil || page["items"].([]map[string]any)[0]["evidence"].(map[string]any)["archive_state"] != "confirmed" {
					t.Fatalf("stream3 history: page=%+v err=%v", page, err)
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
