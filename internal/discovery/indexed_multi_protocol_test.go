package discovery

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIndexedMultipleProtocolsUseArrayMatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`bool_or\(origin = ANY\(string_to_array`).WillReturnRows(sqlmock.NewRows([]string{"identity_key"}))
	if _, err = (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", Protocol: "dhcp,dns_sd", Limit: 20}); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
