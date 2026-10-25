package store

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/evidence"
)

func TestEvidenceBatchWritesOneSetPerKind(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO evidence`).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	items := []evidence.Evidence{
		{EvidenceID: "a", IP: "192.0.2.1", CreatedAt: "2026-10-25T02:00:00Z"},
		{EvidenceID: "b", IP: "192.0.2.2", CreatedAt: "2026-10-25T02:00:00Z"},
	}
	if err := (&PostgresStore{db: db}).WriteEvidence(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceBatchPreservesRepeatedKeyOrder(t *testing.T) {
	runs, err := partitionEvidence([]evidence.Evidence{{EvidenceID: "a", Score: 1}, {EvidenceID: "b", Score: 2}, {EvidenceID: "a", Score: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || len(runs[0]) != 2 || len(runs[1]) != 1 || runs[1][0].Score != 3 {
		t.Fatalf("evidence transition order lost: %#v", runs)
	}
}
