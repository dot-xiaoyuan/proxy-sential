package controlplane

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

type noIdentityOnPolicyRead struct{ store.Reader }

func (noIdentityOnPolicyRead) ListPolicySessions(context.Context, time.Time) ([]policy.Session, error) {
	panic("policy list must not scan identity for empty or shared/quota executions")
}
func TestPolicyExecutionReadSkipsUnrelatedIdentity(t *testing.T) {
	for _, populated := range []bool{false, true} {
		state := &operationsState{doc: emptyOperationsDocument()}
		if populated {
			state.doc.PolicyExecutions["shared"] = policy.Execution{ID: "shared", Definition: policy.Definition{Trigger: "shared_access"}, EvidenceIDs: []string{"shared-evidence"}}
		}
		s := &Server{operations: state, reader: noIdentityOnPolicyRead{}}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/policy-executions", nil)
		s.handlePolicies(w, r, "/policy-executions")
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
}
func TestPolicyReadsReturnDatabaseFailureWithoutOperationsReload(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://unused:unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s := &Server{operations: &operationsState{db: db, doc: emptyOperationsDocument()}, reader: noIdentityOnPolicyRead{}}
	for _, path := range []string{"/policies", "/policy-executions"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1"+path, nil)
		s.handlePolicies(w, r, path)
		if w.Code != 503 {
			t.Fatalf("%s: want 503, got %d", path, w.Code)
		}
	}
}
