package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityDerivedReadyBatchBoundsBeforeLeasing(t *testing.T) {
	for _, tc := range []struct {
		name                                           string
		count, bytes, remainingRecords, remainingBytes int
	}{
		{"records", 50, 100, 49, 1000}, {"bytes", 1, 1001, 50, 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, _ := sqlmock.New()
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch", "first", "state", "lease", "active", "offset", "count", "valid"}).AddRow("a", 0, "pending", nil, false, 50, tc.count, true))
			if tc.count <= tc.remainingRecords {
				mock.ExpectQuery(`SELECT octet_length`).WithArgs("a", 0).WillReturnRows(sqlmock.NewRows([]string{"bytes"}).AddRow(tc.bytes))
			}
			mock.ExpectRollback()
			tx, _ := db.Begin()
			_, err := (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReadyTx(context.Background(), tx, 0, &identityDerivedBatchBudget{Records: tc.remainingRecords, Bytes: tc.remainingBytes})
			tx.Rollback()
			if !errors.Is(err, errIdentityDerivedBatchFull) {
				t.Fatalf("got %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdentityDerivedReadyBatchCommitsLeasesTogether(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	at := time.Now().UTC()
	lease := at.Add(time.Minute)
	mock.ExpectBegin()
	for _, id := range []string{"a", "b"} {
		mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch", "first", "state", "lease", "active", "offset", "count", "valid"}).AddRow(id, 0, "pending", nil, false, 1, 1, true))
		mock.ExpectQuery(`SELECT octet_length`).WithArgs(id, 0).WillReturnRows(sqlmock.NewRows([]string{"bytes"}).AddRow(4))
		mock.ExpectQuery(`UPDATE identity_ingest_fragments SET derived_state='attempted'`).WithArgs(id, 0).WillReturnRows(sqlmock.NewRows([]string{"epoch", "until"}).AddRow(7, lease))
		mock.ExpectExec(`UPDATE identity_derived_ready SET available_at=\$3`).WithArgs(id, 0, lease).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(`SELECT f.batch_id,b.scope_key`).WithArgs(id, 0).WillReturnRows(sqlmock.NewRows([]string{"batch", "scope", "source", "epoch", "month", "hash", "scheme", "first", "count", "accepted", "payload"}).AddRow(id, "scope", "source", "epoch", "202610", "hash", "source_position_v1", 0, 1, at, []byte(`[{}]`)))
	}
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	got, err := (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReadyBatch(context.Background(), 0)
	if err != nil || len(got) != 2 || got[0].DerivedLeaseEpoch != 7 || !got[1].Accepted.Equal(at) {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyBatchRollsBackEarlierLeasesOnLaterFailure(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	at := time.Now().UTC()
	lease := at.Add(time.Minute)
	failure := errors.New("connection lost")
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch", "first", "state", "lease", "active", "offset", "count", "valid"}).AddRow("a", 0, "pending", nil, false, 1, 1, true))
	mock.ExpectQuery(`SELECT octet_length`).WithArgs("a", 0).WillReturnRows(sqlmock.NewRows([]string{"bytes"}).AddRow(4))
	mock.ExpectQuery(`UPDATE identity_ingest_fragments SET derived_state='attempted'`).WithArgs("a", 0).WillReturnRows(sqlmock.NewRows([]string{"epoch", "until"}).AddRow(7, lease))
	mock.ExpectExec(`UPDATE identity_derived_ready SET available_at=\$3`).WithArgs("a", 0, lease).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT f.batch_id,b.scope_key`).WithArgs("a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch", "scope", "source", "epoch", "month", "hash", "scheme", "first", "count", "accepted", "payload"}).AddRow("a", "scope", "source", "epoch", "202610", "hash", "source_position_v1", 0, 1, at, []byte(`[{}]`)))
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnError(failure)
	mock.ExpectRollback()
	got, err := (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReadyBatch(context.Background(), 0)
	if !errors.Is(err, failure) || len(got) != 0 {
		t.Fatalf("earlier lease escaped failed transaction: %+v %v", got, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
