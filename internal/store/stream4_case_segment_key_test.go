package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func stream4CaseRef(t *testing.T) (StreamBodyRef, []byte, []byte, string) {
	t.Helper()
	id := streamlog.SourceSegmentID(streamlog.Segment{Epoch: "fresh", Source: "device-signals", SourcePath: "/signals/device.jsonl", FileID: "file-a", StartOffset: 0, EndOffset: 100})
	event := normalized.Event{EventID: "stream4-" + id + "-0", SchemaVersion: "v1", Type: "device", SourceEventType: "ndp", Timestamp: "2026-11-03T00:00:00Z"}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202611", Scope: "scope-a", Key: "fresh:" + event.EventID, SHA256: hex.EncodeToString(sum[:])}
	return ref, body, sum[:], id
}

func TestReadStream4CaseEvidenceRequiresFinalizedManifestAndOriginal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		finalized bool
		badBody   bool
		want      error
	}{
		{"finalized", true, false, nil},
		{"pending", false, false, streamlog.ErrUnconfirmed},
		{"wrong_original", true, true, streamlog.ErrContentConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, body, hash, id := stream4CaseRef(t)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("FROM jsonb_to_recordset").WithArgs([]byte(`[]`)).
				WillReturnRows(sqlmock.NewRows([]string{"epoch", "scope", "key", "sha256", "body_ref"}))
			accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
			var finalized any
			if tc.finalized {
				finalized = accepted.Add(time.Second)
			}
			mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
				WithArgs([]byte(`["` + id + `"]`)).
				WillReturnRows(sqlmock.NewRows(stream3CaseColumns).AddRow(id, ref.Epoch, "device-signals", "/signals/device.jsonl", "manifest", "stream4", int64(0), 1, accepted, accepted, finalized, "file-a", int64(0), int64(100), ref.Month, "", "stream4", ref.Scope, hash, []byte(`["applied"]`)))
			mock.ExpectQuery("(?s)FROM jsonb_to_recordset.*JOIN stream_discovery_receipts").
				WillReturnRows(sqlmock.NewRows([]string{"event_key", "content_sha256", "accepted_at", "result", "body_ref", "archive_state", "archive_segment_id"}))
			mock.ExpectQuery("(?s)SELECT EXISTS\\(.*stream_discovery_event_keys k.*stream_discovery_event_keys_compact k").
				WithArgs(ref.Epoch, ref.Scope, []byte(`["`+ref.Key+`"]`)).
				WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.want == streamlog.ErrUnconfirmed {
					t.Error("pending case fetched ClickHouse original")
					return
				}
				actual := body
				if tc.badBody {
					actual = []byte(`{"changed":true}`)
				}
				row, _ := json.Marshal(map[string]string{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": ref.SHA256, "body": string(actual)})
				_, _ = w.Write(append(row, '\n'))
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			got, err := (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).ReadStreamCaseEvidence(context.Background(), []StreamBodyRef{ref})
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("case error=%v want=%v", err, tc.want)
				}
			} else if err != nil || !bytes.Equal(got[ref].Document, body) {
				t.Fatalf("case original=%s err=%v", got[ref].Document, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
