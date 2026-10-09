package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"proxy-sentinel/internal/store"
)

type pagedAuditContractReader struct{ store.Reader }

func (pagedAuditContractReader) ListAuditLogsPage(context.Context, store.Query) ([]store.AuditLog, store.Page, error) {
	return []store.AuditLog{{AuditID: "visible-audit", Action: "identity.snapshot.commit"}}, store.Page{Total: 1, Limit: 20}, nil
}
func TestAuditLogsPagedResponseMatchesFrontend(t *testing.T) {
	s := &Server{reader: pagedAuditContractReader{}}
	w := httptest.NewRecorder()
	s.handleAuditLogs(w, httptest.NewRequest("GET", "/api/v1/audit-logs", nil))
	var result struct {
		Logs []AuditLog `json:"logs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || len(result.Logs) != 1 {
		t.Fatalf("paged rows absent from frontend contract: %d %s error=%v", w.Code, w.Body.String(), err)
	}
}
