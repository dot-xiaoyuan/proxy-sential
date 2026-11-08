package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestObservationHistoryMetadataCountsRetainedObservations(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	mock.ExpectQuery(`SELECT s.epoch FROM stream_discovery_device_state`).WithArgs("device-a").WillReturnRows(sqlmock.NewRows([]string{"epoch"}))
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM discovery_device_changes_v2`).WithArgs("device-a").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`SELECT count\(\*\) FROM \(SELECT 1 FROM discovery_observations`).WithArgs("device-a", at, 5001).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
	metadata, err := (Repository{DB: db}).DiscoveryHistoryMetadata(context.Background(), "device-a", at)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Total != 7 || !metadata.AsOf.Equal(at) {
		t.Fatalf("metadata=%+v", metadata)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestObservationHistoryPageUsesObservationCursor(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Truncate(time.Millisecond)
	doc := `{"id":"fact-1","event_id":"event-1","origin":"arp","explanation":"ARP 链路层地址声明"}`
	rows := sqlmock.NewRows([]string{"id", "origin", "observed_at", "data"}).
		AddRow("fact-1", "arp", at, []byte(doc)).
		AddRow("fact-2", "arp", at.Add(-time.Minute), []byte(doc))
	mock.ExpectQuery(`SELECT id,origin,observed_at,data FROM discovery_observations`).WithArgs("device-a", at, 2).WillReturnRows(rows)
	page, err := (Repository{DB: db}).ObservationHistoryAt(context.Background(), "device-a", "", 1, at)
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]map[string]any)
	if len(items) != 1 || items[0]["event_id"] != "event-1" || items[0]["kind"] != "arp" || page["has_more"] != true {
		t.Fatalf("page=%+v", page)
	}
	cursor, _ := page["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("expected a next cursor")
	}
	observed, id, err := decodeObservationHistoryCursor("device-a", cursor)
	if err != nil || !observed.Equal(at) || id != "fact-1" {
		t.Fatalf("cursor decode: observed=%v id=%q err=%v", observed, id, err)
	}
	if _, _, err = decodeObservationHistoryCursor("device-b", cursor); err == nil {
		t.Fatal("cursor must not be reusable for another device")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestObservationHistoryPositionLocatesPreviousPageBoundary(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	mock.ExpectQuery(`SELECT s.epoch FROM stream_discovery_device_state`).WithArgs("device-a").WillReturnRows(sqlmock.NewRows([]string{"epoch"}))
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM discovery_device_changes_v2`).WithArgs("device-a").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`SELECT observed_at,id FROM discovery_observations`).WithArgs("device-a", at, int64(39)).WillReturnRows(sqlmock.NewRows([]string{"observed_at", "id"}).AddRow(at, "fact-39"))
	position, err := (Repository{DB: db}).DiscoveryHistoryPosition(context.Background(), "device-a", at, 3, 20)
	if err != nil {
		t.Fatal(err)
	}
	if position.Cursor == "" {
		t.Fatal("expected boundary cursor")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
