package store

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityDerivedErrorCannotUndoCommittedFragment(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fragment := identityExportFragment{BatchID: "batch-1", First: 0, DerivedLeaseEpoch: 3}
	// A commit can succeed even when its response is lost. The cleanup after
	// that ambiguous result must leave the completed fragment and released
	// payload intact; only a still-attempted generation may be retried.
	mock.ExpectExec(`UPDATE identity_ingest_fragments SET derived_state=.*AND derived_state='attempted'`).
		WithArgs("batch-1", 0, int64(3), "attempted", "derived_storage_error").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := (&PostgresStore{db: db}).reportIdentityDerivedFragmentError(context.Background(), fragment, errors.New("commit response lost")); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
