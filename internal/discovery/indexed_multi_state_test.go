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

func TestIndexedHardwareTypeEvidenceStateFilters(t *testing.T) {
	for _, state := range []string{"profile_typed", "ip_product_only,no_type_clue", "revoked", "candidate,identified,profile_typed"} {
		q := DeviceQuery{Mode: "passive", HardwareV2: true, State: state}
		if _, err := buildIndexedDeviceSelection(q); err != nil {
			t.Errorf("v2 state %q: %v", state, err)
		}
		q.HardwareV2 = false
		if _, err := buildIndexedDeviceSelection(q); err == nil {
			t.Errorf("legacy path accepted v2 state %q", state)
		}
	}
}
