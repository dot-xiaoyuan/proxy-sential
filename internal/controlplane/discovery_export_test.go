package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/discovery"
)

func TestDiscoveryExportCompletesOneReadOnlySnapshot(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	observation, _ := json.Marshal(discovery.Observation{ID: "fact-1", Origin: "arp", Node: "campus-204", ObservedAt: now, ValidUntil: now.Add(time.Hour)})
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)WITH trusted_address.*SELECT classification_status,`).WillReturnRows(sqlmock.NewRows([]string{"classification_status", "device_type", "count", "now"}).AddRow("candidate", "", int64(1), now))
	mock.ExpectQuery(`(?s)WITH trusted_address.*SELECT c.identity_key`).WillReturnRows(sqlmock.NewRows([]string{"identity_key", "device_key", "data", "endpoint_id", "role", "confidence", "conflict", "category"}).AddRow("identity-1", "device-1", observation, "", "", 0, false, "identity_only"))
	mock.ExpectCommit()
	w := httptest.NewRecorder()
	(&Server{}).streamDiscoveryDevices(w, context.Background(), discovery.Repository{DB: db}, discovery.DeviceQuery{Mode: "passive"})
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("records=%d body=%s", len(lines), w.Body.String())
	}
	var manifest, end map[string]any
	if err = json.Unmarshal([]byte(lines[0]), &manifest); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(lines[2]), &end); err != nil {
		t.Fatal(err)
	}
	if manifest["record"] != "manifest" || manifest["total"] != float64(1) || end["record"] != "end" || end["count"] != float64(1) || end["complete"] != true {
		t.Fatalf("manifest=%v end=%v", manifest, end)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryExportReportsCountMismatchWithoutCompletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)WITH trusted_address.*SELECT classification_status,`).WillReturnRows(sqlmock.NewRows([]string{"classification_status", "device_type", "count", "now"}).AddRow("candidate", "", int64(1), now))
	mock.ExpectQuery(`(?s)WITH trusted_address.*SELECT c.identity_key`).WillReturnRows(sqlmock.NewRows([]string{"identity_key", "device_key", "data", "endpoint_id", "role", "confidence", "conflict", "category"}))
	mock.ExpectRollback()
	w := httptest.NewRecorder()
	(&Server{}).streamDiscoveryDevices(w, context.Background(), discovery.Repository{DB: db}, discovery.DeviceQuery{Mode: "passive"})
	if !strings.Contains(w.Body.String(), `"record":"error"`) || strings.Contains(w.Body.String(), `"record":"end"`) {
		t.Fatalf("body=%s", w.Body.String())
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
