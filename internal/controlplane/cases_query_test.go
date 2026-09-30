package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
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

func TestFileCaseQueueCanHideRouterObservations(t *testing.T) {
	operations := &operationsState{doc: emptyOperationsDocument()}
	operations.doc.Cases["shared"] = RiskCase{CaseID: "shared", RulesetVersion: "shared-behavior/v10", RiskKind: "shared_access", Status: "new", UpdatedAt: "2026-09-30T07:00:00Z"}
	operations.doc.Cases["router"] = RiskCase{CaseID: "router", RulesetVersion: "router-observation/router-v3", RiskKind: "router_observation", Status: "new", UpdatedAt: "2026-09-30T07:01:00Z"}
	server := &Server{operations: operations}

	list := func(path string) struct {
		Items []RiskCase `json:"items"`
		Page  Page       `json:"page"`
	} {
		t.Helper()
		response := httptest.NewRecorder()
		server.listCases(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("list cases: %d %s", response.Code, response.Body.String())
		}
		var body struct {
			Items []RiskCase `json:"items"`
			Page  Page       `json:"page"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	if body := list("/api/v1/cases"); len(body.Items) != 2 || body.Page.Total != 2 {
		t.Fatalf("router observations should be included by default: %#v", body)
	}
	if body := list("/api/v1/cases?include_router_observations=false"); len(body.Items) != 1 || body.Items[0].RiskKind != "shared_access" || body.Page.Total != 1 {
		t.Fatalf("router observation filter is inconsistent: %#v", body)
	}
}
