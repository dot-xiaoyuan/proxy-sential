package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func routerResetFixture(t *testing.T, beforeFirst string) (*DBStore, sqlmock.Sqlmock, StreamRouterResetRecoveryRequest, *[]string) {
	t.Helper()
	reset := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	first := reset.Add(15 * time.Minute)
	cutover := reset.Add(-4 * 24 * time.Hour)
	event := normalized.Event{EventID: "first", Type: "device", Source: "zeek", SourceEventType: "dhcp", Timestamp: first.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor-a"}}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	ref := StreamBodyRef{Class: "evidence", Month: first.Format("200601"), Scope: "scope-a", Key: "fresh:first", SHA256: hash}
	refJSON, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		queries = append(queries, string(query))
		switch {
		case strings.Contains(string(query), "countIf(indexed_at<"):
			_, _ = w.Write([]byte(beforeFirst + "\n"))
		case strings.Contains(string(query), "FROM stream_router_signal_index"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"indexed_at": first.Format(time.RFC3339Nano), "event_key": ref.Key, "scope_id": ref.Scope,
				"content_sha256": hash, "archive_month": first.Year()*100 + int(first.Month()),
				"retention_class": ref.Class, "observed_at": first.Format(time.RFC3339Nano),
				"protocol": "dhcp", "body_ref": string(refJSON),
			})
		case strings.Contains(string(query), "SELECT scope_id,event_key,content_sha256,body FROM"):
			_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": hash, "body": string(body)})
		case strings.Contains(string(query), "SELECT scope_id,event_key,content_sha256 FROM"):
			_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": hash})
		default:
			t.Errorf("unexpected ClickHouse query: %s", query)
		}
	}))
	t.Cleanup(server.Close)
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	req := StreamRouterResetRecoveryRequest{
		SensorID: "sensor-a", ResetID: "authorized-reset-1", AuthorizationRef: "docs/discovery-data-reset-20261031.md",
		FixedCutoverAt: cutover, FixedCancelID: "fixed-cancel-1", ResetStartedAt: reset,
		ExpectedFirstIndexedAt: first, ExpectedFirstEventKey: ref.Key, ExpectedFirstSHA256: hash,
	}
	return &DBStore{pg: &PostgresStore{db: db}, ch: ch}, mock, req, &queries
}

func TestRestoreStreamRouterAfterResetPreservesCutoverAndAuditsMissingRange(t *testing.T) {
	store, mock, req, queries := routerResetFixture(t, "0\t0")
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs(req.SensorID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT cancel_id,indexed_after FROM stream_router_fresh_cutovers`).WithArgs(req.SensorID).
		WillReturnRows(sqlmock.NewRows([]string{"cancel_id", "indexed_after"}).AddRow(req.FixedCancelID, req.FixedCutoverAt))
	mock.ExpectQuery(`SELECT 1 FROM stream_router_recognition_state`).WithArgs(req.SensorID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT reset_id FROM stream_router_reset_recoveries`).WithArgs(req.SensorID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`INSERT INTO stream_router_reset_recoveries`).
		WithArgs(req.SensorID, req.ResetID, req.FixedCutoverAt, req.FixedCancelID, req.ResetStartedAt,
			req.ExpectedFirstIndexedAt, req.ExpectedFirstEventKey, req.ExpectedFirstSHA256,
			int64(0), int64(0), req.AuthorizationRef).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_router_recognition_state`).
		WithArgs(req.SensorID, req.FixedCutoverAt, req.FixedCancelID, req.ResetStartedAt, fingerprint.DefaultRouterRuleSet().Version).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	proof, err := store.RestoreStreamRouterAfterReset(context.Background(), req)
	if err != nil || proof.BeforeResetRows != 0 || proof.ResetToFirstRows != 0 || !proof.FirstBodyVerified {
		t.Fatalf("recovery proof=%+v err=%v", proof, err)
	}
	if len(*queries) != 4 || !strings.Contains((*queries)[0], "indexed_at<") || !strings.Contains((*queries)[1], "stream_router_signal_index") {
		t.Fatalf("missing index and body proof: %v", *queries)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreStreamRouterAfterResetRejectsRetainedRowsBeforeAnchor(t *testing.T) {
	store, mock, req, _ := routerResetFixture(t, "0\t1")
	if _, err := store.RestoreStreamRouterAfterReset(context.Background(), req); err == nil {
		t.Fatal("recovery skipped a retained index row after reset")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreStreamRouterAfterResetRejectsExistingState(t *testing.T) {
	store, mock, req, _ := routerResetFixture(t, "0\t0")
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs(req.SensorID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT cancel_id,indexed_after FROM stream_router_fresh_cutovers`).WithArgs(req.SensorID).
		WillReturnRows(sqlmock.NewRows([]string{"cancel_id", "indexed_after"}).AddRow(req.FixedCancelID, req.FixedCutoverAt))
	mock.ExpectQuery(`SELECT 1 FROM stream_router_recognition_state`).WithArgs(req.SensorID).
		WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
	mock.ExpectRollback()
	if _, err := store.RestoreStreamRouterAfterReset(context.Background(), req); err == nil {
		t.Fatal("recovery overwrote existing state")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreStreamRouterAfterResetRejectsChangedCutover(t *testing.T) {
	store, mock, req, _ := routerResetFixture(t, "0\t0")
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs(req.SensorID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT cancel_id,indexed_after FROM stream_router_fresh_cutovers`).WithArgs(req.SensorID).
		WillReturnRows(sqlmock.NewRows([]string{"cancel_id", "indexed_after"}).AddRow("another-generation", req.FixedCutoverAt))
	mock.ExpectRollback()
	if _, err := store.RestoreStreamRouterAfterReset(context.Background(), req); err == nil {
		t.Fatal("recovery reused a superseded fixed cutover")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreStreamRouterAfterResetRejectsPriorRecoveryAudit(t *testing.T) {
	store, mock, req, _ := routerResetFixture(t, "0\t0")
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs(req.SensorID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT cancel_id,indexed_after FROM stream_router_fresh_cutovers`).WithArgs(req.SensorID).
		WillReturnRows(sqlmock.NewRows([]string{"cancel_id", "indexed_after"}).AddRow(req.FixedCancelID, req.FixedCutoverAt))
	mock.ExpectQuery(`SELECT 1 FROM stream_router_recognition_state`).WithArgs(req.SensorID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT reset_id FROM stream_router_reset_recoveries`).WithArgs(req.SensorID).
		WillReturnRows(sqlmock.NewRows([]string{"reset_id"}).AddRow("earlier-reset"))
	mock.ExpectRollback()
	if _, err := store.RestoreStreamRouterAfterReset(context.Background(), req); err == nil {
		t.Fatal("recovery ignored an existing audit after state disappeared")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreStreamRouterAfterResetRejectsChangedFirstHash(t *testing.T) {
	store, mock, req, _ := routerResetFixture(t, "0\t0")
	req.ExpectedFirstSHA256 = strings.Repeat("f", 64)
	if _, err := store.RestoreStreamRouterAfterReset(context.Background(), req); err == nil {
		t.Fatal("recovery accepted an index whose first content hash changed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreStreamRouterAfterResetRejectsOldRetentionWindow(t *testing.T) {
	store, mock, req, _ := routerResetFixture(t, "0\t0")
	req.ResetStartedAt = time.Now().UTC().Add(-7 * 24 * time.Hour).Truncate(time.Microsecond)
	if _, err := store.RestoreStreamRouterAfterReset(context.Background(), req); err == nil {
		t.Fatal("recovery accepted a cursor after the short index retention window")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
