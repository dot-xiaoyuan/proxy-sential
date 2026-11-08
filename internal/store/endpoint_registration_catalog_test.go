package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRegistrationCatalogCursorIsBoundToFilters(t *testing.T) {
	q, err := NormalizeEndpointRegistrationQuery(EndpointRegistrationQuery{Search: "  printer  ", Status: "registered", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	cursor := encodeRegistrationCursor(q, "mac:02:00:00:00:00:01")
	q.Cursor = cursor
	if _, err = NormalizeEndpointRegistrationQuery(q); err != nil {
		t.Fatal(err)
	}
	q.Status = "retired"
	if _, err = NormalizeEndpointRegistrationQuery(q); err == nil {
		t.Fatal("cursor reused with different status")
	}
}

func TestRegistrationCatalogExactMACPreventsFuzzyDuplicateLookup(t *testing.T) {
	q, err := NormalizeEndpointRegistrationQuery(EndpointRegistrationQuery{MAC: " 02-AA-BB-CC-DD-01 "})
	if err != nil || q.MAC != "02:aa:bb:cc:dd:01" {
		t.Fatalf("query=%+v err=%v", q, err)
	}
	where, args := registrationCatalogWhere(q)
	if !strings.Contains(where, "primary_mac=$1") || strings.Contains(where, "LIKE") || len(args) != 1 || args[0] != q.MAC {
		t.Fatalf("non-exact duplicate lookup: %s %v", where, args)
	}
	q.Cursor = encodeRegistrationCursor(q, "mac:02:aa:bb:cc:dd:01")
	q.MAC = "02:aa:bb:cc:dd:02"
	if _, err = NormalizeEndpointRegistrationQuery(q); err == nil {
		t.Fatal("cursor reused for different MAC")
	}
	for _, value := range []string{"bad", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} {
		if _, err = NormalizeEndpointRegistrationQuery(EndpointRegistrationQuery{MAC: value}); err == nil {
			t.Fatalf("invalid MAC accepted: %s", value)
		}
	}
}

func TestRegistrationCatalogReadsBoundedCurrentRowsAndSeparateCount(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pg := &PostgresStore{db: db}
	stamp := time.Now().UTC()
	columns := []string{"endpoint_id", "primary_mac", "registration_status", "owner_account", "owner_name", "owner_department", "asset_tag", "ownership_class", "registration_note", "registration_updated_at", "registration_updated_by", "registered_at", "last_seen", "merge_status", "merged_into_endpoint_id", "split_from_endpoint_id", "details"}
	rows := sqlmock.NewRows(columns)
	for _, id := range []string{"mac:02:00:00:00:00:01", "mac:02:00:00:00:00:02"} {
		rows.AddRow(id, id[4:], "registered", "teacher204", "张老师", "信息中心", "A1", "school_asset", "", stamp, "admin", stamp, nil, "merged", "parent-endpoint", "source-endpoint", []byte(`{"name":"一楼打印机","device_type":"printer","registered_ip":"10.0.0.10","location":"一楼"}`))
	}
	mock.ExpectQuery(`(?s)FROM endpoint_entities.*registration_updated_at IS NOT NULL.*registration_status=\$1.*ORDER BY endpoint_id LIMIT \$2`).WithArgs("registered", 2).WillReturnRows(rows)
	page, err := pg.ListEndpointRegistrations(context.Background(), EndpointRegistrationQuery{Status: "registered", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !page.HasMore || page.NextCursor == "" {
		t.Fatalf("page=%+v", page)
	}
	if page.Items[0].RegistrationDetails.RegisteredIP != "10.0.0.10" || page.Items[0].LastSeen != "" {
		t.Fatalf("registration facts confused with observation: %+v", page.Items[0])
	}
	if item := page.Items[0]; item.OwnerAccount != "teacher204" || item.MergeStatus != "merged" || item.MergedIntoEndpointID != "parent-endpoint" || item.SplitFromEndpointID != "source-endpoint" {
		t.Fatalf("editing fields lost from catalog: %+v", item)
	}
	mock.ExpectQuery(`SELECT count\(\*\) FROM endpoint_entities.*registration_status=\$1`).WithArgs("registered").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	meta, err := pg.EndpointRegistrationMetadata(context.Background(), EndpointRegistrationQuery{Status: "registered", Cursor: page.NextCursor})
	if err != nil || meta.Total != 2 {
		t.Fatalf("metadata=%+v err=%v", meta, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
