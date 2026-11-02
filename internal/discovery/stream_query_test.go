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

func TestDiscoveryFreshnessIncludesUnfinalizedSegment(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accepted := time.Now().UTC().Add(-20 * time.Second)
	projected := time.Now().UTC()
	mock.ExpectQuery("(?s)archive_state='pending'.*UNION ALL.*archive_receipt_mode='segment' AND lanes_finalized_at IS NULL").
		WillReturnRows(sqlmock.NewRows([]string{"oldest", "projected", "version"}).AddRow(accepted, projected, int64(10)))
	result, err := (Repository{DB: db}).streamDiscoveryFreshness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if oldest, ok := result["archive_oldest_pending_at"].(time.Time); !ok || !oldest.Equal(accepted) || result["archive_status"] != "delayed" {
		t.Fatalf("segment archive backlog disappeared: %+v", result)
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
	accepted := time.Now().UTC().Add(-10 * time.Second)
	projected := accepted.Add(3 * time.Second)
	mock.ExpectQuery("(?s)FROM stream_discovery_event_keys k JOIN LATERAL.*archive_segment_id.*lanes_finalized_at").WithArgs("fresh-1", "scope-a", "fresh-1:event-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}).AddRow("hash", accepted, projected, "repeat_observation", "pending", []byte(`{"class":"evidence","key":"fresh-1:event-a"}`)))
	beforeRead := time.Now().UTC()
	receipt, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", "fresh-1:event-a")
	afterRead := time.Now().UTC()
	if err != nil || !found || receipt["result"] != "repeat_observation" || receipt["archive_state"] != "pending" {
		t.Fatalf("receipt visibility: %+v %v %v", receipt, found, err)
	}
	observed, ok := receipt["read_observed_at"].(time.Time)
	if !ok || observed.Before(beforeRead) || observed.After(afterRead) || !observed.After(projected) || !receipt["first_accepted_at"].(time.Time).Equal(accepted) {
		t.Fatalf("receipt has no conservative read observation or changed acceptance: %+v", receipt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryCompactReceiptIsQueryVisiblePerEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	key := "fresh-1:stream2-abc"
	mock.ExpectQuery("FROM stream_discovery_event_keys_compact k JOIN LATERAL").WithArgs("fresh-1", "scope-a", key).
		WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}).AddRow("hash", now, now, "applied", "confirmed", []byte(`{"class":"evidence"}`)))
	receipt, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
	if err != nil || !found || receipt["event_key"] != key || receipt["archive_state"] != "confirmed" {
		t.Fatalf("compact receipt visibility: %+v %v %v", receipt, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryReceiptFallsBackForLegacyNonPassiveStream2Key(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	key := "fresh-1:stream2-old-source"
	columns := []string{"content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}
	mock.ExpectQuery("FROM stream_discovery_event_keys_compact k JOIN LATERAL").WithArgs("fresh-1", "scope-a", key).WillReturnRows(sqlmock.NewRows(columns))
	mock.ExpectQuery("(?s)FROM stream_discovery_event_keys k JOIN LATERAL.*NOT EXISTS").WithArgs("fresh-1", "scope-a", key).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("hash", now, now, "applied", "confirmed", []byte(`{"class":"evidence"}`)))
	receipt, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
	if err != nil || !found || receipt["event_key"] != key {
		t.Fatalf("legacy stream2 receipt missing: %+v %v %v", receipt, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryReceiptsMixesLegacyAndCompactKeysInRequestOrder(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	oldKey, newKey := "fresh-1:stream-old", "fresh-1:stream2-new"
	columns := []string{"event_key", "content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}
	mock.ExpectQuery("FROM stream_discovery_event_keys k").WithArgs("fresh-1", "scope-a", []byte(`["`+oldKey+`"]`)).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(oldKey, "old-hash", now, now, "applied", "confirmed", []byte(`{"class":"evidence"}`)))
	mock.ExpectQuery("FROM stream_discovery_event_keys_compact k").WithArgs("fresh-1", "scope-a", []byte(`["`+newKey+`","fresh-1:stream2-missing"]`)).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(newKey, "new-hash", now, now, "applied", "pending", []byte(`{"class":"evidence"}`)))
	mock.ExpectQuery("(?s)FROM stream_discovery_event_keys k.*NOT EXISTS").WithArgs("fresh-1", "scope-a", []byte(`["fresh-1:stream2-missing"]`)).
		WillReturnRows(sqlmock.NewRows(columns))
	items, missing, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), "fresh-1", "scope-a", []string{newKey, oldKey, "fresh-1:stream2-missing"})
	if err != nil || len(items) != 2 || items[0]["event_key"] != newKey || items[1]["event_key"] != oldKey || len(missing) != 1 || missing[0] != "fresh-1:stream2-missing" {
		t.Fatalf("mixed receipt lookup: items=%+v missing=%v err=%v", items, missing, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryReceiptsFallsBackForLegacyNonPassiveStream2Key(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	key := "fresh-1:stream2-old-source"
	columns := []string{"event_key", "content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}
	mock.ExpectQuery("FROM stream_discovery_event_keys_compact k").WithArgs("fresh-1", "scope-a", []byte(`["`+key+`"]`)).WillReturnRows(sqlmock.NewRows(columns))
	mock.ExpectQuery("(?s)FROM stream_discovery_event_keys k.*NOT EXISTS").WithArgs("fresh-1", "scope-a", []byte(`["`+key+`"]`)).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(key, "hash", now, now, "applied", "confirmed", []byte(`{"class":"evidence"}`)))
	items, missing, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), "fresh-1", "scope-a", []string{key})
	if err != nil || len(items) != 1 || len(missing) != 0 || items[0]["event_key"] != key {
		t.Fatalf("legacy stream2 batch receipt missing: %+v %v %v", items, missing, err)
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
	mock.ExpectQuery("FROM jsonb_array_elements_text.*CROSS JOIN LATERAL.*OFFSET 0.*CROSS JOIN LATERAL").
		WithArgs("fresh-1", "scope-a", []byte(`["key-b","key-a","missing"]`)).
		WillReturnRows(sqlmock.NewRows([]string{"event_key", "content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}).
			AddRow("key-a", "hash-a", now, now, "corrected", "confirmed", []byte(`{"class":"evidence"}`)).
			AddRow("key-b", "hash-b", now, now, "repeat_observation", "pending", []byte(`{"class":"evidence"}`)))
	items, missing, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), "fresh-1", "scope-a", []string{"key-b", "key-a", "missing"})
	if err != nil || len(items) != 2 || items[0]["event_key"] != "key-b" || items[1]["event_key"] != "key-a" || len(missing) != 1 || missing[0] != "missing" {
		t.Fatalf("batch receipt mismatch: items=%+v missing=%v err=%v", items, missing, err)
	}
	for _, item := range items {
		if observed, ok := item["read_observed_at"].(time.Time); !ok || observed.Before(now) || observed.After(time.Now().UTC()) {
			t.Fatalf("batch receipt has no read observation: %+v", item)
		}
	}
	if _, _, err := (Repository{DB: db}).StreamDiscoveryReceipts(context.Background(), "fresh-1", "scope-a", []string{"duplicate", "duplicate"}); err == nil {
		t.Fatal("duplicate key was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
