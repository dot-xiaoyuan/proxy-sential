package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDiscoveryMetadataUsesIndependentFilteredCount(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_DISCOVERY_V2", "")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ", "")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_STREAM_CURRENT_READ", "")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)GROUP BY identity_key.*matched AS.*classification_status.*SELECT count`).WillReturnRows(sqlmock.NewRows([]string{"total", "as_of"}).AddRow(23, time.Now().UTC()))
	server := &Server{operations: &operationsState{db: db}}
	request := httptest.NewRequest("GET", "/discovery/devices/metadata?mode=passive&type=access_point&state=identified&cursor=ignored&limit=bad&offset=99", nil)
	response := httptest.NewRecorder()
	server.handleDiscovery(response, request, "/discovery/devices/metadata")
	if response.Code != 200 {
		t.Fatalf("metadata status=%d body=%s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["total"] != float64(23) || result["count_unit"] != "trusted_discovery_identity" {
		t.Fatalf("result=%v", result)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
