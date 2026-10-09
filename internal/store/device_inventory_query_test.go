package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"testing"
	"time"
)

func TestDeviceInventoryLightQueryOnlyReadsLimitPlusOneAndCachedStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := &PostgresStore{db: db}
	now := time.Now().UTC()
	for request := 0; request < 2; request++ {
		rows := sqlmock.NewRows([]string{"list_item", "updated_at"})
		for i := 0; i < 21; i++ {
			raw, _ := json.Marshal(DeviceInventoryListItem{EndpointID: fmt.Sprintf("fixture-%d", i), CurrentIP: "192.0.2.1"})
			rows.AddRow(raw, now.Add(-time.Duration(i)*time.Second))
		}
		mock.ExpectQuery(`SELECT r.list_item,r.updated_at.*`).WithArgs(21, 0).WillReturnRows(rows).RowsWillBeClosed()
		if request == 0 {
			mock.ExpectQuery(`SELECT\s+EXISTS\(SELECT 1 FROM endpoint_recognition_jobs`).WillReturnRows(sqlmock.NewRows([]string{"updating"}).AddRow(true))
		}
		stages := map[string]bool{}
		page, err := s.ListDeviceInventory(WithDeviceInventoryTiming(context.Background(), func(stage string, _ time.Duration) { stages[stage] = true }), Query{Limit: 20, InventorySkipMetadata: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 20 || page.Page.Total != 0 || page.Page.NextCursor == nil || *page.Page.NextCursor != "20" {
			t.Fatalf("page: %+v", page)
		}
		if page.AsOf != now.Add(-19*time.Second).Format(time.RFC3339Nano) {
			t.Fatalf("sentinel changed freshness: %s", page.AsOf)
		}
		if stages["facets"] || stages["count"] || !stages["pool"] || !stages["page"] {
			t.Fatalf("stages: %+v", stages)
		}
	}
	// Any facet, count, per-terminal history or full catalog read would fail these strict expectations.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceInventoryMetadataNeverReadsRowsOrHistories(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &PostgresStore{db: db}
	mock.ExpectQuery(`SELECT DISTINCT r.filter_brand,r.filter_os_family`).WillReturnRows(sqlmock.NewRows([]string{"brand", "os"}).AddRow("Dell", "Windows"))
	mock.ExpectQuery(`SELECT count\(\*\)`).WillReturnRows(sqlmock.NewRows([]string{"total"}).AddRow(35001))
	page, err := s.ListDeviceInventory(context.Background(), Query{InventoryMetadataOnly: true})
	if err != nil || page.Page.Total != 35001 || len(page.Items) != 0 || page.AsOf == "" {
		t.Fatalf("metadata: %+v %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
