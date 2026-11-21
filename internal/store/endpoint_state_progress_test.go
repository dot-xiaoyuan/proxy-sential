package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEndpointStateProgressStopsAtFailedBatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pg := &PostgresStore{db: db}
	base := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
	changes := []endpointStateChange{
		{id: "a", stamp: base},
		{id: "b", stamp: base.Add(time.Second)},
		{id: "c", stamp: base.Add(2 * time.Second)},
	}
	position := endpointStateKey{}
	processed := 0
	mock.ExpectExec("UPDATE endpoint_state_watermark SET cursors=").WillReturnResult(sqlmock.NewResult(0, 1))
	failed := errors.New("batch failed")
	count, err := pg.processEndpointStateChanges(context.Background(), "entities", changes, 2, &position, func(_ context.Context, ids []string) error {
		processed++
		if processed == 2 {
			return failed
		}
		if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
			t.Fatalf("unexpected first batch: %v", ids)
		}
		return nil
	})
	if !errors.Is(err, failed) {
		t.Fatalf("got %v, want failed batch", err)
	}
	if count != 2 {
		t.Fatalf("processed %d rows, want the two checkpointed rows", count)
	}
	if position.ID != "b" || position.At != base.Add(time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("cursor advanced past failed batch: %+v", position)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointStateRoundContinuesOtherSourcesAfterFailure(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pg := &PostgresStore{db: db}
	base := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	cursors := `{"entities":{"at":"2026-11-21T10:00:00Z","id":"old"},"recognition":{"at":"2026-11-21T10:00:00Z"},"sessions":{"at":"2026-11-21T10:00:00Z"},"projection":{"at":"2026-11-21T10:00:00Z"},"leases":{"at":"2026-11-21T10:00:00Z"},"notes":{"at":"2026-11-21T10:00:00Z"}}`
	mock.ExpectQuery("SELECT cursors,bootstrap_cursor,bootstrap_complete").
		WillReturnRows(sqlmock.NewRows([]string{"cursors", "bootstrap_cursor", "bootstrap_complete"}).AddRow(cursors, "", true))
	mock.ExpectQuery("SELECT endpoint_id,revision FROM identity_endpoint_invalidations").
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id", "revision"}))
	failed := errors.New("entities scan unavailable")
	mock.ExpectQuery("SELECT endpoint_id,updated_at FROM endpoint_entities").
		WithArgs(base, "old", endpointStateSourceLimit).WillReturnError(failed)
	for _, query := range []string{
		"SELECT endpoint_id,updated_at FROM endpoint_recognition_summary",
		"SELECT endpoint_id,updated_at FROM account_sessions",
		"SELECT document->>'endpoint_id',confirmed_at FROM account_identity_session_projection",
	} {
		mock.ExpectQuery(query).WithArgs(base, "", endpointStateSourceLimit).
			WillReturnRows(sqlmock.NewRows([]string{"endpoint_id", "updated_at"}))
	}
	mock.ExpectQuery("SELECT endpoint_id,observed_at FROM device_address_leases").
		WithArgs(base, "", endpointStateSourceLimit).
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id", "observed_at"}).AddRow("new", base.Add(time.Second)))
	mock.ExpectQuery("WITH ids AS").WillReturnRows(sqlmock.NewRows([]string{"endpoint_id"}))
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL synchronous_commit = off").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DELETE FROM endpoint_inventory_lookup").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DELETE FROM endpoint_inventory_accounts").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	mock.ExpectExec("UPDATE endpoint_state_watermark SET cursors=").
		WithArgs("leases", []byte(`{"at":"2026-11-21T10:00:01Z","id":"new"}`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT endpoint_id,updated_at FROM device_name_notes").
		WithArgs(base, "", endpointStateSourceLimit).
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id", "updated_at"}))
	mock.ExpectQuery("SELECT endpoint_id FROM endpoint_entities").
		WithArgs("", endpointStateSweep).WillReturnRows(sqlmock.NewRows([]string{"endpoint_id"}))
	mock.ExpectExec("UPDATE endpoint_state_watermark SET cursors=").WillReturnResult(sqlmock.NewResult(0, 1))
	if count, err := pg.endpointStateRound(context.Background()); count != 1 || !errors.Is(err, failed) {
		t.Fatalf("got count=%d err=%v, want one committed lease row and the entities error", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
