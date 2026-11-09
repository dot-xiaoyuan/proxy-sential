package discovery

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIndexedRandomMACFilterUsesLocalBit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`CASE WHEN coalesce\(l\.data->>'mac'`).WillReturnRows(sqlmock.NewRows([]string{"identity_key"}))
	if _, err = (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", RandomMAC: true, Limit: 20}); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
