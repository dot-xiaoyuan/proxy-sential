package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityDerivedFreshStartRequiresMatchingImmutableLedger(t *testing.T) {
	for _, missing := range []bool{false, true} {
		db, mock, _ := sqlmock.New()
		pg := &PostgresStore{db: db, sensorID: "ncu"}
		after := time.Date(2026, 10, 29, 5, 11, 29, 0, time.UTC)
		expect := mock.ExpectQuery(`SELECT accepted_after FROM identity_derived_fresh_starts`).WithArgs("cutover", "ncu")
		if missing {
			expect.WillReturnError(sql.ErrNoRows)
		} else {
			expect.WillReturnRows(sqlmock.NewRows([]string{"after"}).AddRow(after))
		}
		err := pg.loadIdentityDerivedCutover(context.Background(), "cutover")
		if missing && (err == nil || !pg.identityDerivedAfter.IsZero()) {
			t.Fatal("missing ledger silently enabled an unaudited boundary")
		}
		if !missing && (err != nil || !pg.identityDerivedAfter.Equal(after) || pg.identityDerivedCutoverID != "cutover") {
			t.Fatalf("cutover not loaded: %+v %v", pg.identityDerivedAfter, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}
