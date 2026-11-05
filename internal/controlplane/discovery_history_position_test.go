package controlplane

import (
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDiscoveryHistoryMetadataAndPositionRoutes(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	stamp := time.Now().UTC()
	snapshot := url.QueryEscape(stamp.Format(time.RFC3339Nano))
	call := func(path string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		s.handleDiscovery(w, r, r.URL.Path)
		if w.Code != want {
			t.Fatalf("%s = %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/discovery/history/metadata", "/discovery/history/position?device_id=a&page=0", "/discovery/history/position?device_id=a&limit=101", "/discovery/history/metadata?device_id=a&snapshot=invalid"} {
		call(path, 400)
	}
	mock.ExpectQuery("SELECT s.epoch FROM stream_discovery_device_state s").WithArgs("a").WillReturnRows(sqlmock.NewRows([]string{"epoch"}))
	mock.ExpectQuery(`SELECT count\(\*\) FROM discovery_device_changes_v2`).WithArgs("a", stamp).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
	call("/discovery/history/metadata?device_id=a&snapshot="+snapshot, 200)
	call("/discovery/history/position?device_id=a&page=1&limit=50&snapshot="+snapshot, 200)
	mock.ExpectQuery("SELECT s.epoch FROM stream_discovery_device_state s").WithArgs("a").WillReturnRows(sqlmock.NewRows([]string{"epoch"}))
	mock.ExpectQuery(`SELECT change_id FROM discovery_device_changes_v2.*LIMIT 2 OFFSET`).WithArgs("a", stamp, int64(1)).WillReturnRows(sqlmock.NewRows([]string{"change_id"}).AddRow(1))
	call("/discovery/history/position?device_id=a&page=2&limit=2&snapshot="+snapshot, 400)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
