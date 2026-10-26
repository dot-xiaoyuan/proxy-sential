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

type scopedClaimKeys struct {
	want []string
}

func (m scopedClaimKeys) Match(value driver.Value) bool {
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
		ID string `json:"subject_id"`
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != len(m.want) {
		return false
	}
	for i := range rows {
		if rows[i].ID != m.want[i] {
			return false
		}
	}
	return true
}

func TestScopedRiskCommitsStableClaimsAndRequeuesChangedGeneration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	asOf := time.Date(2026, 10, 26, 3, 0, 0, 0, time.UTC)
	stable := RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 4, ClaimUntil: asOf.Add(time.Minute)}
	changed := RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.9", Generation: 5, ClaimUntil: asOf.Add(time.Minute)}
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(scopedClaimKeys{[]string{stable.ID, changed.ID}}).WillReturnRows(
		sqlmock.NewRows([]string{"subject_type", "subject_id"}).AddRow(stable.Type, stable.ID))
	mock.ExpectExec(`UPDATE risk_feature_dirty_subjects q SET claim_until=NULL`).WithArgs(scopedClaimKeys{[]string{changed.ID}}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at`).WithArgs(scopedClaimKeys{[]string{stable.ID}}).WillReturnRows(
		sqlmock.NewRows([]string{"subject_type", "subject_id", "content_sha256", "observed_at"}))
	mock.ExpectExec(`INSERT INTO stream_risk_current`).WithArgs(scopedClaimKeys{[]string{stable.ID}}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_risk_changes`).WithArgs(scopedClaimKeys{[]string{stable.ID}}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(scopedClaimKeys{[]string{stable.ID}}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	snapshots := []risk.Snapshot{
		{IP: stable.ID, Score: 70, Level: "high", UpdatedAt: asOf.Add(-time.Minute).Format(time.RFC3339Nano)},
		{IP: changed.ID, Score: 60, Level: "medium", UpdatedAt: asOf.Add(-time.Minute).Format(time.RFC3339Nano)},
	}
	committed, err := store.ApplyStreamRiskEvaluation(context.Background(), stable.SensorID, []RiskSubjectClaim{stable, changed}, nil, snapshots, asOf)
	if err != nil || committed != 1 {
		t.Fatalf("stable claim was not committed independently: committed=%d err=%v", committed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

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
	claim := RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 11, ClaimUntil: asOf.Add(time.Minute)}
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id"}).AddRow(claim.Type, claim.ID))
	mock.ExpectQuery(`SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id", "content_sha256", "observed_at"}).AddRow("ip", claim.ID, "prior-hash", asOf.Add(-10*time.Minute)))
	mock.ExpectExec(`DELETE FROM stream_risk_current`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_risk_changes`).WithArgs(emptyRiskChangeEvidenceArray{}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	if _, err := store.ApplyStreamRiskEvaluation(context.Background(), claim.SensorID, []RiskSubjectClaim{claim}, nil, nil, asOf); err != nil {
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
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 9, ClaimUntil: asOf.Add(time.Minute)}}
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id"}).AddRow(claims[0].Type, claims[0].ID))
	mock.ExpectQuery(`SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id", "content_sha256", "observed_at"}))
	mock.ExpectExec(`INSERT INTO stream_risk_current`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_risk_changes`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	snapshot := risk.Snapshot{IP: "192.0.2.8", Score: 70, Level: "high", Window: "10m", UpdatedAt: asOf.Add(-time.Minute).Format(time.RFC3339Nano), EvidenceIDs: []string{"stream-fact"}}
	if _, err := store.ApplyStreamRiskEvaluation(context.Background(), "sensor-a", claims, nil, []risk.Snapshot{snapshot}, asOf); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScopedRiskLeaseChangeRequeuesWithoutPublishing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id"}))
	mock.ExpectExec(`UPDATE risk_feature_dirty_subjects q SET claim_until=NULL`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	committed, err := store.ApplyStreamRiskEvaluation(context.Background(), "sensor-a", []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 9, ClaimUntil: time.Now().UTC().Add(time.Minute)}}, nil, nil, time.Now().UTC())
	if err != nil || committed != 0 {
		t.Fatalf("lost claim was acknowledged: committed=%d err=%v", committed, err)
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
	claim := RiskSubjectClaim{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8", Generation: 10, ClaimUntil: asOf.Add(time.Minute)}
	snapshot := risk.Snapshot{IP: claim.ID, Score: 70, Level: "high", Window: "10m", UpdatedAt: asOf.Add(-time.Minute).Format(time.RFC3339Nano), EvidenceIDs: []string{"stable-rule"}}
	semantic := snapshot
	semantic.UpdatedAt = ""
	hash, err := riskJSONHash(semantic)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`WITH locked AS`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id"}).AddRow(claim.Type, claim.ID))
	mock.ExpectQuery(`SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at`).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"subject_type", "subject_id", "content_sha256", "observed_at"}).AddRow("ip", claim.ID, hash, asOf.Add(-2*time.Minute)))
	mock.ExpectExec(`INSERT INTO stream_risk_current`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	if _, err := store.ApplyStreamRiskEvaluation(context.Background(), "sensor-a", []RiskSubjectClaim{claim}, nil, []risk.Snapshot{snapshot}, asOf); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unchanged risk interpretation wrote a full history row: %v", err)
	}
}
