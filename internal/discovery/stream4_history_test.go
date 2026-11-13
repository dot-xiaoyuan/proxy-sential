package discovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

func TestDeviceStream4HistoryRequiresExactManifestReference(t *testing.T) {
	id, segment := stream4TestSegment()
	key := segment.Epoch + ":" + segment.Events[1].EventID
	accepted := segment.AcceptedAt.Truncate(time.Microsecond)
	hashes := bytes.Repeat([]byte{0x11}, 32)
	for _, tc := range []struct {
		name          string
		refHash       string
		legacyPresent bool
		wantErr       bool
	}{
		{"valid", hex.EncodeToString(hashes), false, false},
		{"wrong_hash", hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)), false, true},
		{"old_key_collision", hex.EncodeToString(hashes), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ref := []byte(`{"class":"evidence","epoch":"fresh","month":"202611","scope":"scope-a","key":"` + key + `","sha256":"` + tc.refHash + `"}`)
			mock.ExpectQuery(`(?s)CASE WHEN left\(c.event_key.*FROM stream_discovery_changes c`).WithArgs(segment.Epoch, "device-a", int64(0), 21).
				WillReturnRows(sqlmock.NewRows([]string{"change_id", "event_key", "accepted_at", "observed_at", "change_kind", "before_hash", "after_hash", "body_ref", "archive_state", "legacy_present"}).
					AddRow(int64(7), key, accepted, accepted, "applied", "", "after", ref, nil, tc.legacyPresent))
			if !tc.legacyPresent {
				mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
					WithArgs([]byte(`["` + id + `"]`)).
					WillReturnRows(sqlmock.NewRows(stream3ReceiptColumns).AddRow(id, segment.Epoch, segment.Source, segment.SourcePath, "manifest", "stream4", int64(0), 1, accepted, accepted, accepted.Add(time.Second), segment.FileID, segment.StartOffset, segment.EndOffset, segment.ArchiveMonth, "", "stream4", "scope-a", hashes, []byte(`["applied"]`)))
				expectNoStream3Diagnostics(mock)
				mock.ExpectQuery("(?s)SELECT EXISTS\\(.*stream_discovery_event_keys k.*stream_discovery_event_keys_compact k").
					WithArgs(segment.Epoch, "scope-a", []byte(`["`+key+`"]`)).
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			}
			page, err := (Repository{DB: db}).streamDiscoveryHistory(context.Background(), segment.Epoch, "device-a", "", 20)
			if tc.wantErr {
				if !errors.Is(err, streamlog.ErrContentConflict) {
					t.Fatalf("bad history accepted: %v", err)
				}
			} else if err != nil || page["items"].([]map[string]any)[0]["evidence"].(map[string]any)["archive_state"] != "confirmed" {
				t.Fatalf("valid history: %+v err=%v", page, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
