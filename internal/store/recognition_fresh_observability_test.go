package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/recognitiondiag"
)

func TestFreshSnapshotCountsOnlyContributingEventAndDimension(t *testing.T) {
	s := freshJobSnapshot{}
	s.Summary.Brand, s.Summary.OS = "Dell", "Windows"
	s.Summary.Conflict, s.Summary.Conflicts = true, []string{"model"}
	s.Summary.Evidence = []fingerprint.DimensionEvidence{
		{Dimension: "brand", Value: "Dell", Layer: "model_catalog", Field: "ssdp_model", Confidence: .95, Refs: []fingerprint.EvidenceRef{{EventID: "other"}}},
		{Dimension: "os_family", Value: "Windows", Layer: "device_rule", Field: "snmp_sysdescr", Confidence: .9, Refs: []fingerprint.EvidenceRef{{EventID: "current"}}},
		{Dimension: "brand", Value: "Dell", Layer: "device_rule", Field: "hostname", Confidence: .6, Refs: []fingerprint.EvidenceRef{{EventID: "current"}}},
	}
	got := freshSnapshotJob(s, "current")
	if got.Candidates != 2 || got.Conclusions != 1 || got.Reason == "conflict" {
		t.Fatalf("unrelated event/conflict or weak evidence inflated conclusions: %+v", got)
	}
	s.Summary.Conflicts = []string{"os_family"}
	got = freshSnapshotJob(s, "current")
	if got.Conclusions != 0 || got.Reason != "conflict" {
		t.Fatalf("contributing dimension conflict was hidden: %+v", got)
	}
	if got = freshSnapshotJob(s, ""); got.Candidates != 0 || got.Conclusions != 0 {
		t.Fatalf("missing event reference must not count unrelated evidence: %+v", got)
	}
}

func TestFreshObserverRollsBackFailedReceiptWrite(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db}}
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	input, _ := json.Marshal(recognitiondiag.Input{Protocol: "ssdp", Parsed: true, ValidUntil: at.Add(time.Hour), Targets: []recognitiondiag.Target{{Endpoint: "e", Generation: 3}}})
	for _, fail := range []bool{true, false} {
		mock.ExpectBegin()
		mock.ExpectQuery("WITH picked AS MATERIALIZED").WillReturnRows(sqlmock.NewRows([]string{"month", "epoch", "scope", "key", "accepted", "input", "result", "now", "jobs"}).AddRow(at, "fresh", "scope", "key", at, input, []byte(`{"last_error":"prior failure"}`), at.Add(10*time.Second), []byte(`[{"endpoint_id":"e","processed":3,"completed_at":"2026-10-28T12:00:03Z","summary":{}}]`)))
		write := mock.ExpectExec("UPDATE stream_discovery_receipts r SET").WithArgs(sqlmock.AnyArg())
		if fail {
			write.WillReturnError(errors.New("write failed"))
			mock.ExpectRollback()
		} else {
			write.WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
		}
		n, err := s.observeFreshRecognition(context.Background())
		if fail && (err == nil || n != 0) || !fail && (err != nil || n != 1) {
			t.Fatalf("n=%d err=%v fail=%v", n, err, fail)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
