package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/pagination"
)

func TestIndexedPositionReadsOnlyTwoBoundaryKeys(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := Repository{DB: db}
	q := DeviceQuery{Mode: "passive", Limit: 20}
	at := time.Now().UTC()
	mock.ExpectQuery(`(?s)WITH trusted_address.*recognition.*candidate_rows.*SELECT identity_key,device_key,last_seen FROM matched.*LIMIT 2 OFFSET`).WillReturnRows(sqlmock.NewRows([]string{"identity_key", "device_key", "last_seen"}).AddRow("anchor", "key", at).AddRow("next", "next-key", at.Add(-time.Second)))
	pos, err := r.DevicesIndexedPosition(context.Background(), q, 3)
	if err != nil || pos.Page != 3 || pos.Limit != 20 || pos.Cursor == "" {
		t.Fatalf("position=%+v err=%v", pos, err)
	}
	normalized, _ := buildIndexedDeviceSelection(q)
	normalized.Query.Cursor = pos.Cursor
	decoded, err := decodeIndexedDeviceCursor(normalized.Query)
	if err != nil || decoded.IdentityKey != "anchor" {
		t.Fatalf("cursor=%+v err=%v", decoded, err)
	}
	mock.ExpectQuery(`(?s)WITH trusted_address.*recognition.*candidate_rows.*LIMIT 2 OFFSET`).WillReturnRows(sqlmock.NewRows([]string{"identity_key", "device_key", "last_seen"}).AddRow("last", "last-key", at))
	if _, err = r.DevicesIndexedPosition(context.Background(), q, 4); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("accepted empty page: %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
