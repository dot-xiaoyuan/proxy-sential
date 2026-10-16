package controlplane

import (
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestSharedDecisionCursorUsesStableOrderAndBindsFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{productPolicies: &productPolicyState{db: db}}
	at := time.Now().UTC().Add(-time.Minute)
	mock.ExpectQuery("SELECT document,evaluated_at,decision_id.*trigger_type=.*result=.*ORDER BY evaluated_at DESC,decision_id DESC").WillReturnRows(sqlmock.NewRows([]string{"document", "at", "id"}).AddRow(`{"decision_id":"b"}`, at, "b").AddRow(`{"decision_id":"a"}`, at, "a"))
	w := httptest.NewRecorder()
	s.queryPolicyDecisions(w, httptest.NewRequest("GET", "/policy-decisions?trigger=shared_access&result=matched&limit=1", nil))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var page struct {
		Items  []map[string]any `json:"items"`
		Cursor string           `json:"next_cursor"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0]["decision_id"] != "b" || page.Cursor == "" {
		t.Fatal(w.Body.String())
	}
	bad := httptest.NewRecorder()
	s.queryPolicyDecisions(bad, httptest.NewRequest("GET", "/policy-decisions?trigger=shared_access&result=insufficient&cursor="+url.QueryEscape(page.Cursor), nil))
	if bad.Code != 400 {
		t.Fatal("cursor reused across filters")
	}
	mock.ExpectQuery("SELECT document,evaluated_at,decision_id.*\\(evaluated_at,decision_id\\)<.*ORDER BY evaluated_at DESC,decision_id DESC").WillReturnRows(sqlmock.NewRows([]string{"document", "at", "id"}).AddRow(`{"decision_id":"a"}`, at, "a"))
	next := httptest.NewRecorder()
	s.queryPolicyDecisions(next, httptest.NewRequest("GET", "/policy-decisions?trigger=shared_access&result=matched&limit=1&cursor="+url.QueryEscape(page.Cursor), nil))
	if next.Code != 200 {
		t.Fatal(next.Body.String())
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
