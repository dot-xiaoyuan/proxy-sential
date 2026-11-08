package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/pagination"
)

func TestInventoryPositionDoesNotLoadDevicePayloadOrMetadata(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &PostgresStore{db: db}
	at := time.Now().UTC()
	mock.ExpectQuery(`SELECT bootstrap_complete,last_error,last_success_at,updated_at FROM endpoint_state_watermark`).WillReturnRows(sqlmock.NewRows([]string{"complete", "error", "success", "at"}).AddRow(true, "", at, at))
	mock.ExpectQuery(`(?s)SELECT i.endpoint_id,i.last_seen FROM endpoint_inventory_lookup.*lower\(r.filter_brand\).*LIMIT 2 OFFSET`).WithArgs("Dell", int64(39)).WillReturnRows(sqlmock.NewRows([]string{"endpoint_id", "last_seen"}).AddRow("end-40", at).AddRow("end-41", nil))
	page, err := s.ListDeviceInventory(context.Background(), Query{Limit: 20, Brand: "Dell", InventoryPositionPage: 3, InventorySkipMetadata: true})
	if err != nil || len(page.Items) != 0 || page.Page.NextCursor == nil {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	c, err := decodeInventoryCursor(Query{Brand: "Dell", InventorySearchType: "all"}, *page.Page.NextCursor)
	if err != nil || c.Endpoint != "end-40" {
		t.Fatalf("cursor=%+v err=%v", c, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationPositionRejectsFullLastPageBoundary(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &PostgresStore{db: db}
	q := EndpointRegistrationQuery{Limit: 20, Status: "registered"}
	mock.ExpectQuery(`SELECT endpoint_id FROM endpoint_entities.*registration_status=\$1.*LIMIT 2 OFFSET \$2`).WithArgs("registered", int64(19)).WillReturnRows(sqlmock.NewRows([]string{"endpoint_id"}).AddRow("last"))
	if _, err = s.EndpointRegistrationPosition(context.Background(), q, 2); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("accepted empty page: %v", err)
	}
	mock.ExpectQuery(`SELECT endpoint_id FROM endpoint_entities.*LIMIT 2 OFFSET`).WithArgs("registered", int64(39)).WillReturnRows(sqlmock.NewRows([]string{"endpoint_id"}).AddRow("end-40").AddRow("end-41"))
	pos, err := s.EndpointRegistrationPosition(context.Background(), q, 3)
	if err != nil || pos.Cursor == "" {
		t.Fatalf("position=%+v err=%v", pos, err)
	}
	q.Cursor = pos.Cursor
	id, err := decodeRegistrationCursor(q)
	if err != nil || id != "end-40" {
		t.Fatalf("cursor=%s err=%v", id, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
