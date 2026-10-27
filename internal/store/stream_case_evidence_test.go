package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestReadStreamCaseEvidenceNeedsArchiveReceiptAndVerifiedBody(t *testing.T) {
	event := normalized.Event{EventID: "event-1", SchemaVersion: "v1", Type: "discovery", Timestamp: "2026-10-24T10:00:00Z"}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-1", SHA256: hex.EncodeToString(sum[:])}
	refJSON, _ := json.Marshal(ref)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("FROM jsonb_to_recordset").WillReturnRows(sqlmock.NewRows([]string{"epoch", "scope_id", "event_key", "content_sha256", "body_ref"}).AddRow(ref.Epoch, ref.Scope, ref.Key, ref.SHA256, refJSON))
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
	if err != nil || string(got[ref].Document) != string(body) {
		t.Fatalf("verified case evidence unavailable: %s %v", got[ref].Document, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadStreamCaseEvidenceRejectsUnconfirmedReceipt(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ref := StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-1", SHA256: strings.Repeat("a", 64)}
	mock.ExpectQuery("FROM jsonb_to_recordset").WillReturnRows(sqlmock.NewRows([]string{"epoch", "scope_id", "event_key", "content_sha256", "body_ref"}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "unexpected body lookup") }))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).ReadStreamCaseEvidence(context.Background(), []StreamBodyRef{ref}); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("unconfirmed archive was accepted for a case: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadStreamSharedCaseEvidenceNeedsFinalizedReceipt(t *testing.T) {
	event := normalized.Event{EventID: "event-1", SchemaVersion: "v1", Source: "handshake-sidecar", Type: "device", Timestamp: "2026-10-25T10:00:00Z"}
	body, _ := json.Marshal(event)
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-1", SHA256: hex.EncodeToString(sum[:])}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		row, _ := json.Marshal(map[string]string{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": ref.SHA256, "body": string(body)})
		_, _ = w.Write(append(row, '\n'))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).ReadStreamSharedCaseEvidence(context.Background(), []StreamBodyRef{ref})
	if err != nil || string(got[ref].Document) != string(body) {
		t.Fatalf("finalized shared case original unavailable: %s %v", got[ref].Document, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadStreamSharedCaseEvidenceBatchesProtectedOriginals(t *testing.T) {
	events := []normalized.Event{
		{EventID: "one", SchemaVersion: "v1", Source: "handshake-sidecar", Type: "device", Timestamp: "2026-10-25T10:00:00Z"},
		{EventID: "two", SchemaVersion: "v1", Source: "handshake-sidecar", Type: "device", Timestamp: "2026-10-25T10:00:01Z"},
	}
	refs := make([]StreamBodyRef, len(events))
	rows := make([]map[string]string, len(events))
	for index, event := range events {
		body, _ := json.Marshal(event)
		sum := sha256.Sum256(body)
		refs[index] = StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:" + event.EventID, SHA256: hex.EncodeToString(sum[:])}
		rows[index] = map[string]string{"scope_id": refs[index].Scope, "event_key": refs[index].Key, "content_sha256": refs[index].SHA256, "body": string(body)}
	}
	queries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(query), "(scope_id,event_key) IN") && !strings.Contains(string(query), "(scope_id,event_key,content_sha256) IN") {
			t.Errorf("case body lookup was not bounded to exact keys: %s", query)
		}
		queries++
		for _, row := range rows {
			_ = json.NewEncoder(w).Encode(row)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&DBStore{ch: ch}).ReadStreamSharedCaseEvidence(context.Background(), refs)
	if err != nil || len(got) != 2 || queries != 2 || string(got[refs[0]].Document) != rows[0]["body"] || string(got[refs[1]].Document) != rows[1]["body"] {
		t.Fatalf("batch case originals got=%d queries=%d err=%v", len(got), queries, err)
	}
}
