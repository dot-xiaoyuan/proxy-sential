package controlplane

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/store"
)

func TestProtectDiscoveryEvidenceRejectsStreamReferenceWithoutArchiveReader(t *testing.T) {
	ref := store.StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202610", Scope: "scope", Key: "fresh:event", SHA256: strings.Repeat("a", 64)}
	evidence, _ := json.Marshal(map[string]any{"stream_discovery_evidence_refs": []store.StreamBodyRef{ref}})
	if err := (&operationsState{}).protectDiscoveryEvidence(context.Background(), nil, "case", evidence); err == nil {
		t.Fatal("case accepted a stream reference without protected original")
	}
}

func TestProtectDiscoveryEvidenceCopiesVerifiedStreamBodyInsideCaseTransaction(t *testing.T) {
	ref := store.StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202610", Scope: "scope", Key: "fresh:event", SHA256: strings.Repeat("a", 64)}
	evidence, _ := json.Marshal(map[string]any{"stream_discovery_evidence_refs": []store.StreamBodyRef{ref}})
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_discovery_case_evidence").WithArgs("case", "fresh", "scope", "fresh:event", ref.SHA256, sqlmock.AnyArg(), `{"event_id":"event"}`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	s := &operationsState{streamEvidenceLoader: func(context.Context, []store.StreamBodyRef) (map[store.StreamBodyRef]store.StreamCaseEvidence, error) {
		return map[store.StreamBodyRef]store.StreamCaseEvidence{ref: {Document: json.RawMessage(`{"event_id":"event"}`), ContentHash: ref.SHA256}}, nil
	}}
	if err := s.protectDiscoveryEvidence(context.Background(), tx, "case", evidence); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProtectSharedCaseEvidenceNeedsVerifiedOriginal(t *testing.T) {
	ref := store.StreamBodyRef{Epoch: "shared-fresh", Class: "evidence", Month: "202610", Scope: "scope", Key: "shared-fresh:event", SHA256: strings.Repeat("a", 64)}
	evidence, _ := json.Marshal(map[string]any{"stream_shared_evidence_refs": []store.StreamBodyRef{ref}})
	if err := (&operationsState{}).protectDiscoveryEvidence(context.Background(), nil, "case", evidence); err == nil {
		t.Fatal("shared case accepted a source reference without an original reader")
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_shared_case_evidence").WithArgs("case", ref.Epoch, ref.Scope, ref.Key, ref.SHA256, sqlmock.AnyArg(), `{"event_id":"event"}`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	s := &operationsState{streamSharedEvidenceLoader: func(context.Context, []store.StreamBodyRef) (map[store.StreamBodyRef]store.StreamCaseEvidence, error) {
		return map[store.StreamBodyRef]store.StreamCaseEvidence{ref: {Document: json.RawMessage(`{"event_id":"event"}`), ContentHash: ref.SHA256}}, nil
	}}
	if err := s.protectDiscoveryEvidence(context.Background(), tx, "case", evidence); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
