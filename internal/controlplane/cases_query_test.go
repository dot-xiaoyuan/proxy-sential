package controlplane

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/store"
	"testing"
)

type forbiddenCaseAggregation struct{ store.Reader }

func (forbiddenCaseAggregation) GetProxyReviews(context.Context, store.ActivityQuery) (store.ProxyReviewResponse, error) {
	panic("case queue must not aggregate raw evidence")
}
func TestDatabaseCaseQueueDoesNotSynchronizeOnRead(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://unused:unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s := &Server{reader: forbiddenCaseAggregation{}, operations: &operationsState{db: db}}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/cases?limit=20&window=7d", nil)
	w := httptest.NewRecorder()
	s.handleCases(w, r)
	if w.Code != 503 {
		t.Fatalf("want bounded database error, got %d %s", w.Code, w.Body.String())
	}
}
