package store

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
)

type identityTestSliceConverter struct{}

func (identityTestSliceConverter) ConvertValue(value any) (driver.Value, error) {
	if _, ok := value.([]string); ok {
		return "batch-list", nil
	}
	return driver.DefaultParameterConverter.ConvertValue(value)
}

func continuationIdentityFragment(t *testing.T) (identityExportFragment, time.Time) {
	t.Helper()
	accepted := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	events := []normalized.Event{{EventID: "identity-position-1", Type: "identity", Source: "identity-http", Timestamp: accepted.Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": "ncu"}, Subject: map[string]any{"campus_id": "campus", "ip": "192.0.2.1"}, Payload: map[string]any{"access_domain": "domain"}}}
	payload, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return identityExportFragment{BatchID: "batch", Scope: "scope", Source: "identity-http", Epoch: "identity-fresh", Month: "202611", Hash: hex.EncodeToString(sum[:]),
		KeyScheme: "source_position_v1", First: 0, Count: 1, Accepted: accepted, Payload: payload, BodyState: "pending", SearchState: "pending"}, accepted.Add(-time.Hour)
}

func expectIdentityFragmentClaim(mock sqlmock.Sqlmock, fragment identityExportFragment, after time.Time, bodyState, searchState string, lease int64) {
	columns := []string{"batch_id", "scope_key", "source", "stream_epoch", "archive_month", "content_sha256", "key_scheme", "first_ordinal", "record_count", "accepted_at", "normalized_events", "body_state", "search_state"}
	mock.ExpectBegin()
	query, _ := identityExportCandidateQuery("ncu", after)
	if !strings.Contains(query, "ORDER BY b.accepted_at DESC") {
		// The 204 work line still uses the ascending candidate order. This
		// continuation only depends on the claimed fragment and its lease.
		mock.ExpectQuery("ORDER BY b.accepted_at,f.batch_id").WithArgs("ncu", after).
			WillReturnRows(sqlmock.NewRows(columns).AddRow(fragment.BatchID, fragment.Scope, fragment.Source, fragment.Epoch, fragment.Month, fragment.Hash, fragment.KeyScheme, fragment.First, fragment.Count, fragment.Accepted, fragment.Payload, bodyState, searchState))
	} else if bodyState == "completed" {
		mock.ExpectQuery("f.body_state='completed' AND f.search_state<>'completed'").WithArgs("ncu", after).
			WillReturnRows(sqlmock.NewRows(columns).AddRow(fragment.BatchID, fragment.Scope, fragment.Source, fragment.Epoch, fragment.Month, fragment.Hash, fragment.KeyScheme, fragment.First, fragment.Count, fragment.Accepted, fragment.Payload, bodyState, searchState))
	} else {
		mock.ExpectQuery("f.body_state='completed' AND f.search_state<>'completed'").WithArgs("ncu", after).WillReturnRows(sqlmock.NewRows(columns))
		mock.ExpectQuery("ORDER BY b.accepted_at DESC").WithArgs("ncu", after).
			WillReturnRows(sqlmock.NewRows(columns).AddRow(fragment.BatchID, fragment.Scope, fragment.Source, fragment.Epoch, fragment.Month, fragment.Hash, fragment.KeyScheme, fragment.First, fragment.Count, fragment.Accepted, fragment.Payload, bodyState, searchState))
	}
	mock.ExpectQuery("UPDATE identity_ingest_fragments SET lease_epoch").WithArgs(fragment.BatchID, fragment.First).
		WillReturnRows(sqlmock.NewRows([]string{"lease_epoch"}).AddRow(lease))
	mock.ExpectCommit()
}

func expectIdentityBodyReceipt(mock sqlmock.Sqlmock, fragment identityExportFragment, lease int64) {
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE identity_ingest_fragments SET body_state='completed'").
		WithArgs(fragment.BatchID, fragment.First, lease).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE identity_ingest_batches SET export_state='pending'").WithArgs(fragment.BatchID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func expectIdentitySearchReceipt(mock sqlmock.Sqlmock, fragment identityExportFragment, lease int64) {
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE identity_ingest_fragments f SET search_state='completed'").WithArgs(fragment.BatchID, fragment.First, lease).
		WillReturnRows(sqlmock.NewRows([]string{"scope_key"}).AddRow(fragment.Scope))
	mock.ExpectExec("UPDATE identity_export_progress SET exported_records").WithArgs(fragment.Scope, fragment.Count).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE identity_ingest_batches b SET export_state=CASE").WithArgs(fragment.BatchID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("WITH ready AS").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
}

func TestIdentityFragmentExportContinuesSearchWithoutSecondCandidateScan(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "true")
	fragment, after := continuationIdentityFragment(t)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(identityTestSliceConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectIdentityFragmentClaim(mock, fragment, after, "pending", "pending", 1)
	expectIdentityBodyReceipt(mock, fragment, 1)
	mock.ExpectQuery("UPDATE identity_ingest_fragments SET search_state='attempted'").WithArgs(fragment.BatchID, fragment.First, int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"lease_epoch"}).AddRow(2))
	expectIdentitySearchReceipt(mock, fragment, 2)
	var bodyWrites, searchWrites int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(string(payload), "INSERT INTO stream_event_body") {
			bodyWrites++
		} else if strings.HasPrefix(string(payload), "INSERT INTO stream_event_search") {
			searchWrites++
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: &PostgresStore{db: db, sensorID: "ncu", identityDerivedAfter: after}, ch: ch}
	var timing identityExportTiming
	if err := backend.exportIdentityInboxFragmentMeasured(context.Background(), &timing); err != nil || bodyWrites != 1 || searchWrites != 1 {
		t.Fatalf("fragment did not finish both receipts: body=%d search=%d err=%v", bodyWrites, searchWrites, err)
	}
	if timing.Records != fragment.Count || timing.Total <= 0 || timing.Claim <= 0 || timing.BodyIO <= 0 || timing.BodyReceipt <= 0 || timing.SearchClaim <= 0 || timing.SearchIO <= 0 || timing.SearchReceipt <= 0 {
		t.Fatalf("completed fragment omitted a durable phase: %+v", timing)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityFragmentExportBodyReceiptRemainsRecoverableWithoutSearchBudget(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "true")
	fragment, after := continuationIdentityFragment(t)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(identityTestSliceConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectIdentityFragmentClaim(mock, fragment, after, "pending", "pending", 1)
	expectIdentityBodyReceipt(mock, fragment, 1)
	expectIdentityFragmentClaim(mock, fragment, after, "completed", "pending", 2)
	expectIdentitySearchReceipt(mock, fragment, 2)
	var bodyWrites, searchWrites int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(string(payload), "INSERT INTO stream_event_body") {
			bodyWrites++
		} else if strings.HasPrefix(string(payload), "INSERT INTO stream_event_search") {
			searchWrites++
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: &PostgresStore{db: db, sensorID: "ncu", identityDerivedAfter: after}, ch: ch}
	short, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := backend.exportIdentityInboxFragment(short); err != nil || bodyWrites != 1 || searchWrites != 0 {
		t.Fatalf("body receipt did not stop safely: body=%d search=%d err=%v", bodyWrites, searchWrites, err)
	}
	if err := backend.exportIdentityInboxFragment(context.Background()); err != nil || bodyWrites != 1 || searchWrites != 1 {
		t.Fatalf("pending search was not resumed: body=%d search=%d err=%v", bodyWrites, searchWrites, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityFragmentExportAmbiguousSearchKeepsAttemptedUntilVerified(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "true")
	fragment, after := continuationIdentityFragment(t)
	segment, _, err := identityFragmentSegment(fragment)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	item := prepared[0]
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(identityTestSliceConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectIdentityFragmentClaim(mock, fragment, after, "pending", "pending", 1)
	expectIdentityBodyReceipt(mock, fragment, 1)
	mock.ExpectQuery("UPDATE identity_ingest_fragments SET search_state='attempted'").WithArgs(fragment.BatchID, fragment.First, int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"lease_epoch"}).AddRow(2))
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE identity_ingest_fragments SET last_error=").WithArgs(fragment.BatchID, fragment.First, int64(2), "archive_storage_error").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE identity_ingest_batches SET export_state='failed'").WithArgs(fragment.BatchID, "archive_storage_error").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectIdentityFragmentClaim(mock, fragment, after, "completed", "attempted", 3)
	expectIdentitySearchReceipt(mock, fragment, 3)
	var bodyWrites, searchWrites, searchVerifies int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasPrefix(string(payload), "INSERT INTO stream_event_body"):
			bodyWrites++
		case strings.HasPrefix(string(payload), "INSERT INTO stream_event_search"):
			searchWrites++
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.Contains(string(payload), "FROM stream_event_search"):
			searchVerifies++
			row, _ := json.Marshal(map[string]any{"scope_id": item.scope, "event_key": item.key, "content_sha256": item.hash,
				"archive_month": 202611, "retention_class": item.retention, "body_ref": ""})
			_, _ = w.Write(append(row, '\n'))
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: &PostgresStore{db: db, sensorID: "ncu", identityDerivedAfter: after}, ch: ch}
	var attempted identityExportTiming
	if err := backend.exportIdentityInboxFragmentMeasured(context.Background(), &attempted); err == nil || bodyWrites != 1 || searchWrites != 1 {
		t.Fatalf("ambiguous search was acknowledged: body=%d search=%d err=%v", bodyWrites, searchWrites, err)
	}
	if attempted.Records != 0 {
		t.Fatalf("ambiguous search counted as export: %+v", attempted)
	}
	var verified identityExportTiming
	if err := backend.exportIdentityInboxFragmentMeasured(context.Background(), &verified); err != nil || searchWrites != 1 || searchVerifies != 1 {
		t.Fatalf("attempted search was not verified without reinsertion: search=%d verifies=%d err=%v", searchWrites, searchVerifies, err)
	}
	if verified.Records != fragment.Count {
		t.Fatalf("verified search was not counted once: %+v", verified)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
