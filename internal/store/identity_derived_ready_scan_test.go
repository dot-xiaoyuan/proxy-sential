package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type readyKeysMatch []identityDerivedReadyKey

func (want readyKeysMatch) Match(value driver.Value) bool {
	raw, ok := value.([]byte)
	if !ok {
		return false
	}
	var got []identityDerivedReadyKey
	if json.Unmarshal(raw, &got) != nil || len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i].BatchID != want[i].BatchID || got[i].First != want[i].First || got[i].SensorID != want[i].SensorID || !got[i].Accepted.Equal(want[i].Accepted) {
			return false
		}
	}
	return true
}

func TestIdentityDerivedReadyScanRegistersOnlyEligibleKeysAndAdvancesAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT cursor_batch,cursor_ordinal,done,`).WillReturnRows(sqlmock.NewRows([]string{"cursor_batch", "cursor_ordinal", "done", "due"}).AddRow("", -1, false, true))
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("", -1, 2).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "sensor_id", "accepted_at", "ready"}).AddRow("a", 0, "sensor-a", at, true).AddRow("b", 50, "sensor-b", at, false))
	mock.ExpectExec(`INSERT INTO identity_derived_ready`).WithArgs(readyKeysMatch{{BatchID: "a", First: 0, SensorID: "sensor-a", Accepted: at}}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE identity_derived_ready_scan SET cursor_batch=\$1,cursor_ordinal=\$2`).WithArgs("b", 50).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	page, err := (&PostgresStore{db: db}).scanIdentityDerivedReadyPage(context.Background(), 2)
	if err != nil || page.Scanned != 2 || page.Eligible != 1 || page.Done {
		t.Fatalf("page %+v: %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyScanDoesNotAdvanceIfRegistrationFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	failure := errors.New("write failed")
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT cursor_batch,cursor_ordinal,done,`).WillReturnRows(sqlmock.NewRows([]string{"cursor_batch", "cursor_ordinal", "done", "due"}).AddRow("a", 0, false, true))
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("a", 0, 2).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "sensor_id", "accepted_at", "ready"}).AddRow("b", 0, "sensor", time.Now(), true))
	mock.ExpectExec(`INSERT INTO identity_derived_ready`).WithArgs(sqlmock.AnyArg()).WillReturnError(failure)
	mock.ExpectRollback()
	if _, err := (&PostgresStore{db: db}).scanIdentityDerivedReadyPage(context.Background(), 2); !errors.Is(err, failure) {
		t.Fatalf("expected failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyScanFinishesWithoutRevisitingCompletedWork(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT cursor_batch,cursor_ordinal,done,`).WillReturnRows(sqlmock.NewRows([]string{"cursor_batch", "cursor_ordinal", "done", "due"}).AddRow("z", 50, false, true))
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("z", 50, 2).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "sensor_id", "accepted_at", "ready"}))
	mock.ExpectExec(`UPDATE identity_derived_ready_scan SET done=true`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	page, err := (&PostgresStore{db: db}).scanIdentityDerivedReadyPage(context.Background(), 2)
	if err != nil || page.Scanned != 0 || !page.Done {
		t.Fatalf("page %+v: %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyScanHonorsSharedRateLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT cursor_batch,cursor_ordinal,done,`).WillReturnRows(sqlmock.NewRows([]string{"cursor_batch", "cursor_ordinal", "done", "due"}).AddRow("a", 0, false, false))
	mock.ExpectCommit()
	page, err := (&PostgresStore{db: db}).scanIdentityDerivedReadyPage(context.Background(), 256)
	if err != nil || !page.Deferred || page.Scanned != 0 {
		t.Fatalf("shared rate limit bypassed: %+v %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyProgressRangeCoversEveryCrossedFragment(t *testing.T) {
	// Migration 178 limits a fragment to 50 records. Even the longest fragment
	// crossing the old offset must begin at or after old-49; the trigger may use
	// that bounded index range without dropping a fragment.
	for old := 0; old < 180; old++ {
		for next := old + 1; next <= old+60; next++ {
			for first := 0; first <= next; first++ {
				for count := 1; count <= 50; count++ {
					if first+count > old && first+count <= next && (first < max(0, old-49) || first >= next) {
						t.Fatalf("crossed fragment outside bounded range: old=%d next=%d first=%d count=%d", old, next, first, count)
					}
				}
			}
		}
	}
}
