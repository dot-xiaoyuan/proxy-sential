package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/risk"
)

type emptyRiskChangeEvidenceArray struct{}

func (emptyRiskChangeEvidenceArray) Match(value driver.Value) bool {
	var raw []byte
	switch typed := value.(type) {
	case string:
		raw = []byte(typed)
	case []byte:
		raw = typed
	default:
		return false
	}
	var rows []struct {
		Evidence json.RawMessage `json:"evidence_ids"`
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
		return false
	}
	return string(rows[0].Evidence) == "[]"
}

func TestScopedRiskExpiryRecordsEmptyEvidenceArray(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	asOf := time.Date(2026, 10, 25, 10, 2, 40, 0, time.UTC)
	claim := RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 11}
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id", "content_sha256", "observed_at"}).AddRow("ip", claim.ID, "prior-hash", asOf.Add(-10*time.Minute)))
	mock.ExpectExec(`DELETE FROM stream_risk_current`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_risk_changes`).WithArgs(emptyRiskChangeEvidenceArray{}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	if err := store.ApplyStreamRiskEvaluation(context.Background(), claim.SensorID, []RiskSubjectClaim{claim}, nil, nil, asOf); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScopedRiskCommitFencesGenerationAndWritesOnlyClaimedSubject(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	asOf := time.Date(2026, 10, 25, 4, 30, 0, 0, time.UTC)
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 9}}
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id", "content_sha256", "observed_at"}))
	mock.ExpectExec(`INSERT INTO stream_risk_current`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_risk_changes`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	snapshot := risk.Snapshot{IP: "192.0.2.8", Score: 70, Level: "high", Window: "10m", UpdatedAt: asOf.Add(-time.Minute).Format(time.RFC3339Nano), EvidenceIDs: []string{"stream-fact"}}
	if err := store.ApplyStreamRiskEvaluation(context.Background(), "sensor-a", claims, nil, []risk.Snapshot{snapshot}, asOf); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScopedRiskLeaseChangeRollsBackWithoutPublishing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectRollback()
	store := &DBStore{pg: &PostgresStore{db: db}}
	err = store.ApplyStreamRiskEvaluation(context.Background(), "sensor-a", []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 9}}, nil, nil, time.Now().UTC())
	if err == nil {
		t.Fatal("lost claim was acknowledged")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScopedRiskRepeatRefreshesCurrentWithoutHistoryCopy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	asOf := time.Date(2026, 10, 25, 4, 30, 0, 0, time.UTC)
	claim := RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 10}
	snapshot := risk.Snapshot{IP: claim.ID, Score: 70, Level: "high", Window: "10m", UpdatedAt: asOf.Add(-time.Minute).Format(time.RFC3339Nano), EvidenceIDs: []string{"stable-rule"}}
	semantic := snapshot
	semantic.UpdatedAt = ""
	hash, err := riskJSONHash(semantic)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id", "content_sha256", "observed_at"}).AddRow("ip", claim.ID, hash, asOf.Add(-2*time.Minute)))
	mock.ExpectExec(`INSERT INTO stream_risk_current`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	if err := store.ApplyStreamRiskEvaluation(context.Background(), "sensor-a", []RiskSubjectClaim{claim}, nil, []risk.Snapshot{snapshot}, asOf); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unchanged risk interpretation wrote a full history row: %v", err)
	}
}
