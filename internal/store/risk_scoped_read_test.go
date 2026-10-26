package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

func TestScopedRiskReadKeepsSensorAndSubjectBoundary(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stamp := time.Date(2026, 10, 25, 5, 0, 0, 0, time.UTC)
	item := risk.Snapshot{IP: "192.0.2.8", Score: 70, Level: "high", UpdatedAt: stamp.Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(item)
	semantic := item
	semantic.UpdatedAt = ""
	digest, _ := riskJSONHash(semantic)
	mock.ExpectQuery(`FROM stream_risk_current`).WithArgs("sensor-a", "ip", item.IP).WillReturnRows(sqlmock.NewRows([]string{"snapshot", "observed_at", "content_sha256"}).AddRow(raw, stamp, digest))
	store := &PostgresStore{db: db}
	got, found, err := store.GetStreamRiskSnapshot(context.Background(), "sensor-a", "ip", item.IP)
	if err != nil || !found || got.Score != 70 {
		t.Fatalf("scoped risk result missing: %+v %t %v", got, found, err)
	}
	if _, _, err := store.GetStreamRiskSnapshot(context.Background(), "sensor-b", "ip", ""); err == nil {
		t.Fatal("invalid subject was accepted")
	}
	mock.ExpectQuery(`FROM stream_risk_current`).WithArgs("sensor-a", "ip", item.IP).WillReturnRows(sqlmock.NewRows([]string{"snapshot", "observed_at", "content_sha256"}).AddRow(raw, stamp, "wrong"))
	if _, _, err := store.GetStreamRiskSnapshot(context.Background(), "sensor-a", "ip", item.IP); err == nil {
		t.Fatal("content hash conflict was accepted")
	}
	fact := evidence.Evidence{EvidenceID: "fact-1", IP: item.IP, CreatedAt: stamp.Format(time.RFC3339Nano)}
	factRaw, _ := json.Marshal(fact)
	factHash, _ := riskJSONHash(fact)
	mock.ExpectQuery(`FROM stream_risk_evidence`).WithArgs("sensor-a", "ip", item.IP, 10).WillReturnRows(sqlmock.NewRows([]string{"evidence_id", "content_sha256", "evidence"}).AddRow(fact.EvidenceID, factHash, factRaw))
	facts, err := store.ListStreamRiskEvidence(context.Background(), "sensor-a", "ip", item.IP, 10)
	if err != nil || len(facts) != 1 || facts[0].EvidenceID != fact.EvidenceID {
		t.Fatalf("scoped evidence missing: %+v %v", facts, err)
	}
	mock.ExpectQuery(`FROM stream_risk_evidence`).WithArgs("sensor-a", "ip", item.IP, 10).WillReturnRows(sqlmock.NewRows([]string{"evidence_id", "content_sha256", "evidence"}).AddRow(fact.EvidenceID, "wrong", factRaw))
	if _, err := store.ListStreamRiskEvidence(context.Background(), "sensor-a", "ip", item.IP, 10); err == nil {
		t.Fatal("evidence hash conflict was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScopedRiskReadAcceptsPostgresTimestampPrecision(t *testing.T) {
	observed := time.Date(2026, 10, 26, 4, 9, 59, 795478000, time.UTC)
	item := risk.Snapshot{IP: "192.0.2.8", Score: 27, Level: "normal", UpdatedAt: observed.Add(105 * time.Nanosecond).Format(time.RFC3339Nano)}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	semantic := item
	semantic.UpdatedAt = ""
	digest, err := riskJSONHash(semantic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseScopedRiskSnapshot(raw, observed, digest, "ip", item.IP); err != nil {
		t.Fatalf("PostgreSQL microsecond precision rejected a valid snapshot: %v", err)
	}
	if _, err := parseScopedRiskSnapshot(raw, observed.Add(time.Microsecond), digest, "ip", item.IP); err == nil {
		t.Fatal("a different stored observation was accepted")
	}
}
