package discovery

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIndexedMultipleStatesUseArrayMatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`classification_status = ANY\(string_to_array`).WillReturnRows(sqlmock.NewRows([]string{"identity_key"}))
	if _, err = (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", State: "identified,candidate,conflict", Limit: 20}); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIndexedRejectsInvalidStateInList(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", State: "identified,unknown", Limit: 20}); err == nil {
		t.Fatal("expected invalid state error")
	}
}
