package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDevicesStateLimitsKeysBeforeReadingNewAndLegacyDocuments(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("WITH fresh AS MATERIALIZED").WillReturnRows(sqlmock.NewRows([]string{"device_key", "last_seen", "result_version", "document"}).AddRow("device-new", now, 3, []byte(`{"id":"device-new","generation":"fresh","freshness":"new"}`)))
	mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM stream_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(false))
	mock.ExpectQuery("SELECT.*created_at FROM discovery_batch_work").WillReturnRows(sqlmock.NewRows([]string{"oldest", "ingested", "processed", "failure", "version"}).AddRow(nil, nil, now, nil, int64(3)))
	page, err := (Repository{DB: db}).DevicesState(context.Background(), DeviceQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]map[string]any)
	if len(items) != 1 || items[0]["generation"] != "fresh" {
		t.Fatalf("new generation disappeared: %+v", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryFreshnessDoesNotCountCancelledLegacyWorkAsFreshLag(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM stream_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	mock.ExpectQuery("FROM \\(SELECT DISTINCT epoch FROM stream_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"oldest", "projected", "version"}).AddRow(nil, now, int64(9)))
	result, err := (Repository{DB: db}).DiscoveryFreshness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result["generation"] != "fresh" || result["result_version"] != int64(9) {
		t.Fatalf("new generation freshness missing: %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryHistoryReadsFreshNarrowChanges(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("SELECT s.epoch FROM stream_discovery_device_state s").WithArgs("device-new").WillReturnRows(sqlmock.NewRows([]string{"epoch"}).AddRow("fresh-1"))
	mock.ExpectQuery("FROM stream_discovery_changes c").WithArgs("fresh-1", "device-new", int64(0), 21).WillReturnRows(sqlmock.NewRows([]string{"change_id", "event_key", "accepted_at", "observed_at", "change_kind", "before_hash", "after_hash", "body_ref", "archive_state"}).AddRow(int64(7), "fresh-1:event-a", now, now, "applied", "", "hash", []byte(`{"class":"evidence","month":"202610","scope":"scope-a","key":"fresh-1:event-a","sha256":"hash"}`), "confirmed"))
	page, err := (Repository{DB: db}).DiscoveryHistory(context.Background(), "device-new", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]map[string]any)
	if len(items) != 1 || items[0]["event_id"] != "fresh-1:event-a" {
		t.Fatalf("fresh change missing: %+v", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryReceiptIsQueryVisiblePerEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("FROM stream_discovery_event_keys k JOIN stream_discovery_receipts r").WithArgs("fresh-1", "scope-a", "fresh-1:event-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}).AddRow("hash", now, now, "repeat_observation", "pending", []byte(`{"class":"evidence","key":"fresh-1:event-a"}`)))
	receipt, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", "fresh-1:event-a")
	if err != nil || !found || receipt["result"] != "repeat_observation" || receipt["archive_state"] != "pending" {
		t.Fatalf("receipt visibility: %+v %v %v", receipt, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryReceiptsReturnsBoundedResultsInRequestOrder(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("FROM stream_discovery_event_keys k JOIN stream_discovery_receipts r").
		WithArgs("fresh-1", "scope-a", []byte(`["key-b","key-a","missing"]`)).
		WillReturnRows(sqlmock.NewRows([]string{"event_key", "content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}).
			AddRow("key-a", "hash-a", now, now, "corrected", "confirmed", []byte(`{"class":"evidence"}`)).
			AddRow("key-b", "hash-b", now, now, "repeat_observation", "pending", []byte(`{"class":"evidence"}`)))
	items, missing, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), "fresh-1", "scope-a", []string{"key-b", "key-a", "missing"})
	if err != nil || len(items) != 2 || items[0]["event_key"] != "key-b" || items[1]["event_key"] != "key-a" || len(missing) != 1 || missing[0] != "missing" {
		t.Fatalf("batch receipt mismatch: items=%+v missing=%v err=%v", items, missing, err)
	}
	if _, _, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), "fresh-1", "scope-a", []string{"duplicate", "duplicate"}); err == nil {
		t.Fatal("duplicate key was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
