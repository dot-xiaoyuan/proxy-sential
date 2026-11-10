package discovery

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIndexedMultipleTypesUseArrayMatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`string_to_array\(\$?`).WillReturnRows(sqlmock.NewRows([]string{"identity_key"}))
	if _, err = (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", DeviceType: "printer,camera", Limit: 20}); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
