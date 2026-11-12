package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityBatchSeekUsesBoundedDatabasePage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Add(-time.Minute)
	mock.ExpectQuery("(?s)SELECT batch_id,source,sensor_id,status.*FROM identity_ingest_batches WHERE received_at").
		WithArgs(sqlmock.AnyArg(), 2).
		WillReturnRows(sqlmock.NewRows([]string{"batch_id", "source", "sensor_id", "status", "records_read", "records_emitted", "records_skipped", "records_malformed", "error", "received_at", "retry_count", "last_retried_at"}).
			AddRow("new", "auth", "sensor", "completed", 2, 2, 0, 0, "", at, 0, nil).
			AddRow("old", "auth", "sensor", "completed", 1, 1, 0, 0, "", at.Add(-time.Minute), 0, nil))
	s := &Server{identityIngest: &identityIngestState{db: db}}
	w := httptest.NewRecorder()
	s.handleIdentityBatches(w, httptest.NewRequest("GET", "/integrations/identity/batches?seek=1&limit=1", nil))
	var first struct {
		Items      []IdentityIngestBatch `json:"items"`
		NextCursor string                `json:"next_cursor"`
		HasMore    bool                  `json:"has_more"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || w.Code != 200 || len(first.Items) != 1 || first.Items[0].BatchID != "new" || !first.HasMore {
		t.Fatalf("unexpected seek batch page: %d %s err=%v", w.Code, w.Body.String(), err)
	}
	mock.ExpectQuery("(?s)SELECT batch_id,source,sensor_id,status.*FROM identity_ingest_batches WHERE received_at").
		WithArgs(sqlmock.AnyArg(), at, "new", 2).
		WillReturnRows(sqlmock.NewRows([]string{"batch_id", "source", "sensor_id", "status", "records_read", "records_emitted", "records_skipped", "records_malformed", "error", "received_at", "retry_count", "last_retried_at"}).
			AddRow("old", "auth", "sensor", "completed", 1, 1, 0, 0, "", at.Add(-time.Minute), 0, nil))
	next := httptest.NewRecorder()
	s.handleIdentityBatches(next, httptest.NewRequest("GET", "/integrations/identity/batches?seek=1&limit=1&cursor="+url.QueryEscape(first.NextCursor), nil))
	if next.Code != 200 || !json.Valid(next.Body.Bytes()) {
		t.Fatalf("second page failed: %d %s", next.Code, next.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBatchMemorySeekDoesNotMaterializeWholeHistory(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	state := &identityIngestState{batches: map[string]IdentityIngestBatch{}}
	for i, id := range []string{"first", "second", "third"} {
		state.batches[id] = IdentityIngestBatch{BatchID: id, ReceivedAt: at.Add(time.Duration(-i) * time.Minute).Format(time.RFC3339Nano)}
	}
	s := &Server{identityIngest: state}
	w := httptest.NewRecorder()
	s.handleIdentityBatches(w, httptest.NewRequest("GET", "/integrations/identity/batches?seek=1&limit=2", nil))
	var page struct {
		Items      []IdentityIngestBatch `json:"items"`
		NextCursor string                `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Items) != 2 || page.Items[0].BatchID != "first" || page.Items[1].BatchID != "second" || page.NextCursor == "" {
		t.Fatalf("unexpected memory seek page: %d %s err=%v", w.Code, w.Body.String(), err)
	}
}
