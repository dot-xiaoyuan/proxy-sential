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
	mock.ExpectQuery(`(?s)GROUP BY identity_key.*matched AS.*classification_status.*GROUP BY classification_status`).WillReturnRows(sqlmock.NewRows([]string{"status", "type", "count", "as_of"}).AddRow("identified", "printer", 23, time.Now().UTC()))
	server := &Server{operations: &operationsState{db: db}}
	request := httptest.NewRequest("GET", "/discovery/devices/metadata?mode=passive&type=printer&state=identified&cursor=ignored&limit=bad&offset=99", nil)
	response := httptest.NewRecorder()
	server.handleDiscovery(response, request, "/discovery/devices/metadata")
	if response.Code != 200 {
		t.Fatalf("metadata status=%d body=%s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["total"] != float64(23) || result["identified"] != float64(23) || result["count_unit"] != "trusted_discovery_identity" {
		t.Fatalf("result=%v", result)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryStatisticsReturnsEmptyResultOnIndexedPath(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_DISCOVERY_V2", "")
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{operations: &operationsState{db: db}}
	request := httptest.NewRequest("GET", "/discovery/statistics", nil)
	response := httptest.NewRecorder()
	server.handleDiscovery(response, request, "/discovery/statistics")
	if response.Code != 200 {
		t.Fatalf("statistics status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Items          []any `json:"items"`
		PendingUpdates int   `json:"pending_updates"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Items == nil || len(result.Items) != 0 || result.PendingUpdates != 0 {
		t.Fatalf("indexed statistics should be an empty result, got %+v", result)
	}
}
