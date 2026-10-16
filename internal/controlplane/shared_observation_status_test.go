package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/sharedaccess"
)

func TestSharedStatusDistinguishesIdleCaptureFromNoObservations(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT count").WillReturnRows(sqlmock.NewRows([]string{"pending", "failed", "expired", "matched", "insufficient", "coverage", "identity", "received", "captured", "completed", "oldest"}).AddRow(0, 0, 0, 0, 0, 0, 0, nil, nil, nil, nil))
	mock.ExpectQuery("SELECT count").WillReturnRows(sqlmock.NewRows([]string{"pending", "failed", "at", "received"}).AddRow(0, 0, nil, nil))
	mock.ExpectQuery("SELECT c.sensor_id").WillReturnRows(sqlmock.NewRows([]string{"sensor", "campus", "domain", "source", "instance", "covered", "complete", "stopped"}).AddRow("s", "c", "d", "handshake-sidecar", "one", time.Now(), true, false))
	s := &Server{sharedObservationEnabled: true, readOnly: true, operations: &operationsState{db: db}, sharedConfig: sharedaccess.Config{Sources: []sharedaccess.Source{{SensorID: "s", CampusID: "c", AccessDomain: "d", Source: "handshake-sidecar"}}}}
	rr := httptest.NewRecorder()
	s.sharedObservationStatus(rr, httptest.NewRequest("GET", "/shared-access/status", nil))
	var result struct {
		Collection      struct{ State string }
		Materialization struct{ State string }
		Controller      struct {
			State    string
			Expected bool
		}
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &result) != nil {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if result.Collection.State != "healthy" || result.Materialization.State != "waiting" || result.Controller.State != "disabled" || !result.Controller.Expected {
		t.Fatalf("%s", rr.Body.String())
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
