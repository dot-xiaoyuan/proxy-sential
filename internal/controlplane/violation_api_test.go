package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestViolationMCPListsReadOnlyTools(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	w := httptest.NewRecorder()
	s.handleViolationMCP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "get_violation_case") || strings.Contains(body, "disconnect") || strings.Contains(body, "notify") {
		t.Fatalf("unexpected MCP tools: %s", body)
	}
}

func TestViolationRoutesKeepReadAndWritePermissionsSeparate(t *testing.T) {
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodGet, "/violation-cases", "cases:read"},
		{http.MethodPost, "/mcp", "cases:read"},
		{http.MethodPost, "/violation-cases/v-1/release-preview", "cases:write"},
	} {
		if got := requiredPermission(tc.method, tc.path); got != tc.want {
			t.Fatalf("%s %s permission=%s, want %s", tc.method, tc.path, got, tc.want)
		}
	}
}
