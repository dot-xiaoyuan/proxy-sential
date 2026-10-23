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
	err = pg.processEndpointStateChanges(context.Background(), "entities", changes, 2, &position, func(_ context.Context, ids []string) error {
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
	if position.ID != "b" || position.At != base.Add(time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("cursor advanced past failed batch: %+v", position)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
