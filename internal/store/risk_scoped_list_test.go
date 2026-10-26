package store

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/risk"
)

func TestStreamRiskListPagesCurrentResultsWithoutLoadingEntireSet(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Date(2026, 10, 26, 2, 24, 31, 0, time.UTC)
	observed := cutoff.Add(time.Minute)
	first := risk.Snapshot{IP: "192.0.2.1", Score: 80, Level: "high", UpdatedAt: observed.Format(time.RFC3339Nano)}
	second := risk.Snapshot{IP: "192.0.2.2", Score: 70, Level: "high", UpdatedAt: observed.Format(time.RFC3339Nano)}
	makeRow := func(item risk.Snapshot) []driver.Value {
		t.Helper()
		semantic := item
		semantic.UpdatedAt = ""
		hash, hashErr := riskJSONHash(semantic)
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		raw, marshalErr := json.Marshal(item)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return []driver.Value{raw, hash, observed, "ip", item.IP, item.Level, item.Score}
	}
	mock.ExpectQuery(`SELECT accepted_after FROM stream_risk_fresh_cutovers`).WithArgs("sensor-a").
		WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}).AddRow(cutoff))
	rows := sqlmock.NewRows([]string{"snapshot", "content_sha256", "observed_at", "subject_type", "subject_id", "level", "score"})
	rows.AddRow(makeRow(first)...).AddRow(makeRow(second)...)
	mock.ExpectQuery(`SELECT snapshot,content_sha256,observed_at,subject_type,subject_id,level,score`).WithArgs(
		"sensor-a", "ip", cutoff, "", false, "", 0, "", 2).WillReturnRows(rows)
	page, err := (&PostgresStore{db: db}).ListStreamRiskCurrent(context.Background(), "sensor-a", "ip", "", "", 1)
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].IP != first.IP {
		t.Fatalf("risk list lost bounded cursor: %+v %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRiskListRejectsCursorAcrossFreshCutover(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Date(2026, 10, 26, 3, 0, 0, 0, time.UTC)
	old, _ := json.Marshal(streamRiskCursor{Cutoff: cutoff.Add(-time.Minute), Type: "ip", Level: "high", Score: 70, ID: "192.0.2.1"})
	mock.ExpectQuery(`SELECT accepted_after FROM stream_risk_fresh_cutovers`).WithArgs("sensor-a").
		WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}).AddRow(cutoff))
	_, err = (&PostgresStore{db: db}).ListStreamRiskCurrent(context.Background(), "sensor-a", "ip", "", base64.RawURLEncoding.EncodeToString(old), 20)
	if !errors.Is(err, ErrStreamRiskCursor) {
		t.Fatalf("stale cursor was accepted: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
