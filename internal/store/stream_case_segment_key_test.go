package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

var stream3CaseColumns = []string{"segment_id", "epoch", "source_kind", "source_path", "archive_receipt_mode", "passive_key_scheme", "source_generation", "event_count", "accepted_at", "projected_at", "lanes_finalized_at", "source_file_id", "source_start_offset", "source_end_offset", "archive_month", "body_layout", "key_scheme", "scope_id", "content_hashes", "results"}

func stream3CaseRef(t *testing.T) (StreamBodyRef, []byte, []byte, string) {
	t.Helper()
	id := streamlog.SourceSegmentID(streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", SourcePath: "packet://test", FileID: "capture-a", StartOffset: 0, EndOffset: 100})
	event := normalized.Event{EventID: "stream3-" + id + "-0", SchemaVersion: "v1", Type: "discovery", Timestamp: "2026-11-03T00:00:00Z"}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202611", Scope: "scope-a", Key: "fresh:" + event.EventID, SHA256: hex.EncodeToString(sum[:])}
	return ref, body, sum[:], id
}

func TestReadStream3CaseEvidenceRequiresFinalizedManifestAndOriginal(t *testing.T) {
	ref, body, hash, id := stream3CaseRef(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("FROM jsonb_to_recordset").WithArgs([]byte(`[]`)).
		WillReturnRows(sqlmock.NewRows([]string{"epoch", "scope", "key", "sha256", "body_ref"}))
	accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery("(?s)jsonb_array_elements_text.*stream_projection_segments.*stream_discovery_segment_receipt_manifests").
		WithArgs([]byte(`["` + id + `"]`)).
		WillReturnRows(sqlmock.NewRows(stream3CaseColumns).AddRow(id, ref.Epoch, "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 1, accepted, accepted, accepted.Add(time.Second), "capture-a", int64(0), int64(100), ref.Month, "", "stream3", ref.Scope, hash, []byte(`["applied"]`)))
	mock.ExpectQuery("(?s)FROM jsonb_to_recordset.*JOIN stream_discovery_receipts").
		WillReturnRows(sqlmock.NewRows([]string{"event_key", "content_sha256", "accepted_at", "result", "body_ref", "archive_state", "archive_segment_id"}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		row, _ := json.Marshal(map[string]string{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": ref.SHA256, "body": string(body)})
		_, _ = w.Write(append(row, '\n'))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).ReadStreamCaseEvidence(context.Background(), []StreamBodyRef{ref})
	if err != nil || !bytes.Equal(got[ref].Document, body) {
		t.Fatalf("stream3 case original: got=%s err=%v", got[ref].Document, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadStream3CaseEvidenceRejectsPendingOrMismatchedHashBeforeOriginal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		finalized bool
		wrongHash bool
		want      error
	}{
		{"pending", false, false, streamlog.ErrUnconfirmed},
		{"wrong_hash", true, true, streamlog.ErrContentConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, _, hash, id := stream3CaseRef(t)
			if tc.wrongHash {
				ref.SHA256 = hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
			}
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
				WillReturnRows(sqlmock.NewRows(stream3CaseColumns).AddRow(id, ref.Epoch, "passive-discovery", "packet://test", "manifest", "stream3", int64(0), 1, accepted, accepted, finalized, "capture-a", int64(0), int64(100), ref.Month, "", "stream3", ref.Scope, hash, []byte(`["applied"]`)))
			mock.ExpectQuery("(?s)FROM jsonb_to_recordset.*JOIN stream_discovery_receipts").
				WillReturnRows(sqlmock.NewRows([]string{"event_key", "content_sha256", "accepted_at", "result", "body_ref", "archive_state", "archive_segment_id"}))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("unconfirmed case requested ClickHouse original")
				_, _ = io.WriteString(w, "unexpected")
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, err = (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).ReadStreamCaseEvidence(context.Background(), []StreamBodyRef{ref})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got error %v, want %v", err, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
