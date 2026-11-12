package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityBridgeRunsSeekMergesOnlyBoundedSourcePages(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Add(-time.Minute)
	mock.ExpectQuery("(?s)WITH event_runs AS MATERIALIZED.*bridge_runs AS MATERIALIZED.*LIMIT \\$6").
		WithArgs("ncu-srun4k", ncuIdentityBridgeID, "", "", sqlmock.AnyArg(), 2).
		WillReturnRows(sqlmock.NewRows([]string{"run_id", "kind", "status", "records_read", "records_emitted", "records_skipped", "records_malformed", "retry_count", "duration_ms", "error_type", "started_at", "completed_at"}).
			AddRow("new", "event_batch", "completed", 2, 2, 0, 0, 0, int64(25), "", at, at.Add(time.Second)).
			AddRow("old", "snapshot", "completed", 1, 1, 0, 0, 0, int64(30), "", at.Add(-time.Minute), nil))
	s := &Server{operations: &operationsState{db: db}}
	w := httptest.NewRecorder()
	s.handleIdentityBridgeRuns(w, httptest.NewRequest("GET", "/integrations/identity/bridge/runs?seek=1&limit=1", nil))
	var page struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
		HasMore    bool             `json:"has_more"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Items) != 1 || page.Items[0]["run_id"] != "new" || !page.HasMore {
		t.Fatalf("unexpected identity run seek page: %d %s err=%v", w.Code, w.Body.String(), err)
	}
	wrongFilter := httptest.NewRecorder()
	s.handleIdentityBridgeRuns(wrongFilter, httptest.NewRequest("GET", "/integrations/identity/bridge/runs?seek=1&kind=snapshot&limit=1&cursor="+url.QueryEscape(page.NextCursor), nil))
	if wrongFilter.Code != 400 {
		t.Fatalf("cursor crossed filter boundary: %d %s", wrongFilter.Code, wrongFilter.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
