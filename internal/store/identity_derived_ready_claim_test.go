package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityDerivedReadyClaimUsesBoundedKeyAndFencedLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	lease := at.Add(70 * time.Second)
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "derived_state", "lease_until", "lease_active", "processed_offset", "record_count", "valid_batch"}).AddRow("batch-a", 0, "pending", nil, false, 1, 1, true))
	mock.ExpectQuery(`UPDATE identity_ingest_fragments SET derived_state='attempted'`).WithArgs("batch-a", 0).WillReturnRows(sqlmock.NewRows([]string{"derived_lease_epoch", "derived_lease_until"}).AddRow(7, lease))
	mock.ExpectExec(`UPDATE identity_derived_ready SET available_at=\$3`).WithArgs("batch-a", 0, lease).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT f.batch_id,b.scope_key,b.source,b.stream_epoch`).WithArgs("batch-a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "scope_key", "source", "stream_epoch", "archive_month", "content_sha256", "key_scheme", "first_ordinal", "record_count", "accepted_at", "normalized_events"}).AddRow("batch-a", "scope", "source", "epoch", "202610", "hash", "source_position_v1", 0, 1, at, []byte(`[{}]`)))
	mock.ExpectCommit()
	fragment, err := (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReady(context.Background(), 0)
	if err != nil || fragment.BatchID != "batch-a" || fragment.DerivedLeaseEpoch != 7 || !fragment.Accepted.Equal(at) {
		t.Fatalf("claim %+v: %v", fragment, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyClaimDefersOldApplicationLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	lease := time.Now().UTC().Add(time.Minute)
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 1).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "derived_state", "lease_until", "lease_active", "processed_offset", "record_count", "valid_batch"}).AddRow("batch-a", 0, "attempted", lease, true, 1, 1, true))
	mock.ExpectExec(`UPDATE identity_derived_ready SET available_at=\$3`).WithArgs("batch-a", 0, lease).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	_, err = (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReady(context.Background(), 1)
	if !errors.Is(err, errIdentityDerivedReadyDeferred) {
		t.Fatalf("expected deferred, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyClaimRetiresStaleTerminalKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 1).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "derived_state", "lease_until", "lease_active", "processed_offset", "record_count", "valid_batch"}).AddRow("batch-a", 0, "completed", nil, false, 1, 1, true))
	mock.ExpectExec(`DELETE FROM identity_derived_ready`).WithArgs("batch-a", 0).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	_, err = (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReady(context.Background(), 1)
	if !errors.Is(err, errIdentityDerivedReadyDeferred) {
		t.Fatalf("expected stale-key cleanup, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyClaimNeverSkipsUnreadyKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "derived_state", "lease_until", "lease_active", "processed_offset", "record_count", "valid_batch"}).AddRow("batch-a", 0, "pending", nil, false, 0, 1, true))
	mock.ExpectRollback()
	_, err = (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReady(context.Background(), 0)
	if err == nil || errors.Is(err, sql.ErrNoRows) || errors.Is(err, errIdentityDerivedReadyDeferred) {
		t.Fatalf("expected visible integrity error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDerivedReadyClaimRollsBackLeaseIfQueueUpdateFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	lease := time.Now().UTC().Add(time.Minute)
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("sensor-a", 0).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "first_ordinal", "derived_state", "lease_until", "lease_active", "processed_offset", "record_count", "valid_batch"}).AddRow("batch-a", 0, "pending", nil, false, 1, 1, true))
	mock.ExpectQuery(`UPDATE identity_ingest_fragments SET derived_state='attempted'`).WithArgs("batch-a", 0).WillReturnRows(sqlmock.NewRows([]string{"derived_lease_epoch", "derived_lease_until"}).AddRow(7, lease))
	mock.ExpectExec(`UPDATE identity_derived_ready SET available_at=\$3`).WithArgs("batch-a", 0, lease).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	_, err = (&PostgresStore{db: db, sensorID: "sensor-a"}).claimIdentityDerivedReady(context.Background(), 0)
	if err == nil {
		t.Fatal("missing ready row allowed a fragment lease to commit")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
