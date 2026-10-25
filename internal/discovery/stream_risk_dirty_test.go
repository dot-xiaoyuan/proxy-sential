package discovery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type riskSubjectPayload struct{ count int }

func (m riskSubjectPayload) Match(value driver.Value) bool {
	raw, ok := value.([]byte)
	if !ok {
		text, textOK := value.(string)
		if !textOK {
			return false
		}
		raw = []byte(text)
	}
	var rows []struct {
		Type string `json:"subject_type"`
		ID   string `json:"subject_id"`
	}
	return json.Unmarshal(raw, &rows) == nil && len(rows) == m.count
}

func TestRiskSubjectsQueueOnlyOncePerConfirmedSegment(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	segment := streamlog.Segment{Epoch: "fresh", AcceptedAt: now, Events: []normalized.Event{
		{Type: "device", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"ip": "192.0.2.8", "account_id": "account-a"}},
		{Type: "device", Timestamp: now.Add(time.Second).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"ip": "192.0.2.8", "account_id": "account-a"}},
	}}
	projector := StreamDiscoveryProjector{DB: db}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO risk_feature_segment_receipts`).WithArgs("segment-a", sqlmock.AnyArg(), "fresh", now).WillReturnRows(sqlmock.NewRows([]string{"segment_id"}).AddRow("segment-a"))
	mock.ExpectExec(`INSERT INTO risk_feature_dirty_subjects`).WithArgs(riskSubjectPayload{count: 2}, now).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	if err := projector.MarkStreamRiskSubjectsDirty(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(segment.Events)
	digest := sha256.Sum256(encoded)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO risk_feature_segment_receipts`).WithArgs("segment-a", sqlmock.AnyArg(), "fresh", now).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT segment_sha256 FROM risk_feature_segment_receipts`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"segment_sha256"}).AddRow(hex.EncodeToString(digest[:])))
	mock.ExpectCommit()
	if err := projector.MarkStreamRiskSubjectsDirty(context.Background(), "segment-a", segment); err != nil {
		t.Fatalf("idempotent segment receipt requeued subjects: %v", err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO risk_feature_segment_receipts`).WithArgs("segment-a", sqlmock.AnyArg(), "fresh", now).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT segment_sha256 FROM risk_feature_segment_receipts`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"segment_sha256"}).AddRow("different"))
	mock.ExpectRollback()
	if err := projector.MarkStreamRiskSubjectsDirty(context.Background(), "segment-a", segment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("same segment with changed content was accepted: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
