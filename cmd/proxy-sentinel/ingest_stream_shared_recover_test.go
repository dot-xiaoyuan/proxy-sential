package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRecoverClosedFileSharedGenerationAuditsBothOwners(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Date(2026, 10, 31, 9, 20, 0, 0, time.UTC)
	sources := []sharedSourceActivation{
		{Owner: "handshake-sidecar", Path: "/signals/handshake.jsonl", Epoch: "handshake-fresh", FileCancelID: "handshake-reset"},
		{Owner: "packet-sidecar", Path: "/signals/ttl.jsonl", Epoch: "packet-fresh", FileCancelID: "packet-reset"},
	}
	mock.ExpectBegin()
	for _, src := range sources {
		oldEpoch := src.Owner + "-old"
		encoded, _ := json.Marshal([]string{"sensor", src.Owner, src.Path, oldEpoch, "old-shared", strings.Repeat("a", 64), src.Epoch, src.FileCancelID, "new-shared", cutoff.Format(time.RFC3339Nano)})
		hash := sha256.Sum256(encoded)
		manifest := hex.EncodeToString(hash[:])
		mock.ExpectQuery(`SELECT s.epoch,s.state,f.state,f.cancel_manifest_sha256`).WithArgs("sensor", src.Owner, src.Path, "old-shared").WillReturnRows(sqlmock.NewRows([]string{"epoch", "state", "file_state", "manifest", "cutoff"}).AddRow(src.Owner+"-old", "active", "closed", strings.Repeat("a", 64), cutoff.Add(-time.Hour)))
		mock.ExpectQuery(`SELECT sensor_id,state,legacy_cancel_id,legacy_cutoff_at`).WithArgs(src.Epoch, src.Path).WillReturnRows(sqlmock.NewRows([]string{"sensor", "state", "cancel", "cutoff"}).AddRow("sensor", "active", src.FileCancelID, cutoff))
		mock.ExpectExec(`INSERT INTO stream_discard_manifest`).WithArgs(oldEpoch, src.Path, src.Epoch, manifest).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(`SELECT content_sha256 FROM stream_discard_manifest`).WithArgs(oldEpoch, src.Path, src.Epoch).WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(manifest))
		mock.ExpectExec(`UPDATE stream_shared_source_cutovers SET state='closed'`).WithArgs("sensor", src.Owner, oldEpoch, "old-shared").WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectCommit()
	if err := recoverClosedFileSharedGeneration(context.Background(), db, "sensor", sources, "old-shared", "new-shared", cutoff); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverClosedFileSharedGenerationRejectsOpenFileSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Date(2026, 10, 31, 9, 20, 0, 0, time.UTC)
	src := sharedSourceActivation{Owner: "packet-sidecar", Path: "/signals/ttl.jsonl", Epoch: "fresh", FileCancelID: "reset"}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT s.epoch,s.state,f.state,f.cancel_manifest_sha256`).WithArgs("sensor", src.Owner, src.Path, "old-shared").WillReturnRows(sqlmock.NewRows([]string{"epoch", "state", "file_state", "manifest", "cutoff"}).AddRow("old", "active", "active", strings.Repeat("a", 64), cutoff.Add(-time.Hour)))
	mock.ExpectRollback()
	if err := recoverClosedFileSharedGeneration(context.Background(), db, "sensor", []sharedSourceActivation{src, {Owner: "handshake-sidecar", Path: "/signals/handshake.jsonl", Epoch: "other"}}, "old-shared", "new-shared", cutoff); err == nil {
		t.Fatal("active old file source must prevent recovery")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
