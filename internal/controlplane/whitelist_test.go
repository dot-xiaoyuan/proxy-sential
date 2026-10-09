package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/policy"
	"strings"
	"testing"
	"time"
)

func whitelistFixture() policy.WhitelistEntry {
	return policy.WhitelistEntry{Type: "account", Value: "student", Reason: "教学测试账号", Enabled: true}
}

func TestWhitelistPersistenceRevisionAndLateDeliveryReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "whitelist.json")
	m := newWhitelistManager(nil, path)
	e, err := m.save(ctx, whitelistFixture(), "", "create", "admin")
	if err != nil {
		t.Fatal(err)
	}
	second := newWhitelistManager(nil, path)
	ss := &Server{whitelist: second}
	for _, action := range []string{"disconnect", "notify", "rate_limit", "disable_account", "quarantine", "throttle"} {
		if err := ss.checkActionWhitelist(ctx, EnforcementAction{ActionType: action, AccountID: "student"}); err == nil || !strings.Contains(err.Error(), "whitelist_suppressed") {
			t.Fatal("late queued action bypassed whitelist", action, err)
		}
	}
	if err := ss.validateSharedDisconnectDelivery(ctx, EnforcementAction{ActionType: "disconnect", AccountID: "student"}); err == nil || !strings.Contains(err.Error(), "whitelist_suppressed") {
		t.Fatal("manual native delivery bypassed whitelist", err)
	}
	if err := ss.checkActionWhitelist(ctx, EnforcementAction{ActionType: "release", AccountID: "student"}); err != nil {
		t.Fatal("recovery blocked", err)
	}
	if _, err = m.save(ctx, policy.WhitelistEntry{Revision: e.Revision}, e.ID, "disable", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = second.save(ctx, e, e.ID, "update", "other"); !errors.Is(err, errWhitelistConflict) {
		t.Fatal("stale edit overwritten", err)
	}
	items, err := second.list(ctx)
	if err != nil || len(items) != 1 || items[0].Enabled {
		t.Fatal("disable did not persist", items, err)
	}
	if _, err = second.save(ctx, whitelistFixture(), "", "create", "admin"); !errors.Is(err, errWhitelistDuplicate) {
		t.Fatal("duplicate admitted", err)
	}
	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	var retry actionPrecheckReadError
	if err = ss.checkActionWhitelist(ctx, EnforcementAction{ActionType: "disconnect", AccountID: "student"}); !errors.As(err, &retry) {
		t.Fatal("corrupt configuration failed open", err)
	}
}

func TestWhitelistStopsApprovedManualStageReplay(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	_, err := s.whitelist.save(context.Background(), whitelistFixture(), "", "create", "admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ss := []policy.Session{{ID: "s", AccountID: "student", Source: "auth", CampusID: "ncu", AccessDomain: "wired", IP: "192.0.2.10", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}}
	bindings, _ := policy.SessionApprovalBindings("student", ss, now)
	e := policy.Execution{ID: "round", AccountID: "student", Definition: policy.Definition{Mode: "manual", Stages: []policy.Stage{{Action: "disconnect", ConnectorID: "c"}}}, Stages: []policy.StageState{{Key: "stage", ApprovedSessionBindings: bindings}}}
	s.createPolicyActionsLocked(&e, 0, ss, now)
	if len(s.operations.doc.Actions) != 0 || e.State != "whitelist_suppressed" || e.Stages[0].Status != "cancelled" {
		t.Fatal("approved action bypassed exemption", e)
	}
	if requiredPermission("GET", "/whitelist") != "policies:read" || requiredPermission("POST", "/whitelist/x/disable") != "policies:manage" {
		t.Fatal("incorrect whitelist permission")
	}
}

func TestWhitelistAPIManagementReplay(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir()})
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), sessionContextKey{}, Session{User: User{ID: "admin"}}))
		result := httptest.NewRecorder()
		s.handleWhitelist(result, req, path)
		return result
	}
	result := call(http.MethodPost, "/whitelist", `{"type":"network","value":"192.0.2.1/24","reason":"实验教学网段","enabled":true,"revision":0}`)
	if result.Code != 201 {
		t.Fatal(result.Code, result.Body.String())
	}
	var e policy.WhitelistEntry
	if err := json.Unmarshal(result.Body.Bytes(), &e); err != nil || e.Value != "192.0.2.0/24" || e.CreatedBy != "admin" {
		t.Fatal(e, err)
	}
	// Exercise request query separately from the route passed to dispatch.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whitelist?type=network&state=active&keyword=教学", nil)
	result = httptest.NewRecorder()
	s.handleWhitelist(result, req, "/whitelist")
	var page struct {
		Items []policy.WhitelistEntry `json:"items"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].ID != e.ID {
		t.Fatal(result.Body.String(), err)
	}
	raw, _ := json.Marshal(map[string]int{"revision": e.Revision})
	result = call(http.MethodPost, "/whitelist/"+e.ID+"/disable", string(raw))
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body.String())
	}
	result = call(http.MethodPost, "/whitelist/"+e.ID+"/enable", string(raw))
	if result.Code != 409 {
		t.Fatal("stale write accepted", result.Code, result.Body.String())
	}
	for _, body := range []string{`{}`, `{"type":"ip","value":"bad","reason":"测试","enabled":true}`, `{} {}`} {
		if result = call(http.MethodPost, "/whitelist", body); result.Code != 400 {
			t.Fatal("invalid input accepted", result.Code, result.Body.String())
		}
	}
	// The public handler must enforce the global read-only switch.
	ro := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	result = httptest.NewRecorder()
	ro.Handler().ServeHTTP(result, httptest.NewRequest(http.MethodPost, "/api/v1/whitelist", strings.NewReader(`{}`)))
	if result.Code != http.StatusForbidden {
		t.Fatal("read-only mutation admitted", result.Code, result.Body.String())
	}
}
