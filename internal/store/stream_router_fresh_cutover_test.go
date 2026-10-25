package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/fingerprint"
)

func TestStreamRouterFreshCutoverRejectsUnsettledNewIndexRows(t *testing.T) {
	query := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query = string(body)
		_, _ = w.Write([]byte("5\t1\n"))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT fresh_cutoff_at,lease_until>now\(\),processed_events FROM stream_router_recognition_state`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"fresh_cutoff_at", "leased", "processed_events"}))
	mock.ExpectRollback()
	store := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
	if _, err := store.StartStreamRouterFreshCutover(context.Background(), "sensor-a", "cancel-1", cutoff); err == nil {
		t.Fatal("cutover skipped already indexed new input")
	}
	if !strings.Contains(query, "stream_router_signal_index") || !strings.Contains(query, "countIf(indexed_at>=") {
		t.Fatalf("router index cutover count omitted boundary: %s", query)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRouterFreshCutoverStoresExactCanceledCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("5\t0\n"))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT fresh_cutoff_at,lease_until>now\(\),processed_events FROM stream_router_recognition_state`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"fresh_cutoff_at", "leased", "processed_events"}))
	mock.ExpectExec(`INSERT INTO stream_router_fresh_cutovers`).WithArgs("sensor-a", "cancel-1", cutoff, uint64(5), int64(0)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_router_recognition_state`).WithArgs("sensor-a", cutoff, "cancel-1", fingerprint.DefaultRouterRuleSet().Version).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
	count, err := store.StartStreamRouterFreshCutover(context.Background(), "sensor-a", "cancel-1", cutoff)
	if err != nil || count != 5 {
		t.Fatalf("router index cutover audit missing: count=%d err=%v", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRouterFreshCutoverReseedsStoppedSecondGeneration(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query = string(body)
		_, _ = w.Write([]byte("9\t0\n"))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	prior := cutoff.Add(-time.Hour)
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT fresh_cutoff_at,lease_until>now\(\),processed_events FROM stream_router_recognition_state`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"fresh_cutoff_at", "leased", "processed_events"}).AddRow(prior, false, int64(42)))
	mock.ExpectExec(`INSERT INTO stream_router_fresh_cutovers`).WithArgs("sensor-a", "cancel-2", cutoff, uint64(9), int64(42)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE stream_router_recognition_state SET fresh_cutoff_at`).WithArgs("sensor-a", cutoff, "cancel-2", fingerprint.DefaultRouterRuleSet().Version).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
	count, err := store.StartStreamRouterFreshCutover(context.Background(), "sensor-a", "cancel-2", cutoff)
	if err != nil || count != 9 || !strings.Contains(query, "indexed_at>=") {
		t.Fatalf("second router generation was not bounded by prior cutoff: count=%d err=%v query=%s", count, err, query)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
