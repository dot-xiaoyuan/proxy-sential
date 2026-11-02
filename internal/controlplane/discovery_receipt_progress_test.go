package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDiscoveryReceiptBatchKeepsMissingKeysWithCheckTime(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("FROM stream_discovery_event_keys k").WithArgs("fresh-1", "scope-a", []byte(`["missing"]`)).
		WillReturnRows(sqlmock.NewRows([]string{"event_key", "content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}))
	mock.ExpectQuery("SELECT k.event_key FROM jsonb_array_elements_text").WithArgs("fresh-1", "scope-a", []byte(`["missing"]`)).
		WillReturnRows(sqlmock.NewRows([]string{"event_key"}))
	server := &Server{operations: &operationsState{db: db}}
	request := httptest.NewRequest("GET", "/discovery/receipts?epoch=fresh-1&scope_id=scope-a&event_key=missing", nil)
	response := httptest.NewRecorder()
	beforeRead := time.Now().UTC()
	server.handleDiscovery(response, request, "/discovery/receipts")
	afterRead := time.Now().UTC()
	if response.Code != 200 {
		t.Fatalf("receipt batch status = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Items       []json.RawMessage `json:"items"`
		MissingKeys []string          `json:"missing_keys"`
		CheckedAt   time.Time         `json:"checked_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 0 || len(body.MissingKeys) != 1 || body.MissingKeys[0] != "missing" || body.CheckedAt.Before(beforeRead) || body.CheckedAt.After(afterRead) {
		t.Fatalf("missing receipt was hidden or lost check time: %+v", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
