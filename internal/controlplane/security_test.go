package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/risk"
)

func TestBootstrapAdminDoesNotOverwriteExistingCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if err := BootstrapAdmin(path, "admin", "管理员", "long-password-123"); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapAdmin(path, "other", "其他管理员", "other-password-123"); err == nil {
		t.Fatal("expected existing auth file to be protected")
	}
}

func TestFileUserLifecyclePersistsAndInvalidatesSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if err := BootstrapAdmin(path, "admin", "管理员", "long-password-123"); err != nil {
		t.Fatal(err)
	}
	manager, err := newAuthManager(path, false, "")
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.createUser(context.Background(), userMutation{Username: "reviewer", Name: "复核员", Role: "reviewer", Password: "reviewer-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.login("192.0.2.2:1", "reviewer", "reviewer-password-123"); err != nil {
		t.Fatal(err)
	}
	updated, err := manager.updateUser(context.Background(), created.ID, "disable", userMutation{})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Disabled {
		t.Fatalf("expected disabled user: %#v", updated)
	}
	reloaded, err := newAuthManager(path, false, "")
	if err != nil {
		t.Fatal(err)
	}
	items, err := reloaded.listUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || !items[1].Disabled {
		t.Fatalf("user lifecycle was not persisted: %#v", items)
	}
}

func TestCampusExceptionDowngradesAssessmentAndBlocksAutomation(t *testing.T) {
	manager := newExceptionManager(nil)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := manager.save(context.Background(), CampusException{ExceptionID: "exception-1", ScopeType: "ip", ScopeValue: "10.0.0.8", Reason: "校园 WebVPN", RulesetVersion: "v1", ValidFrom: now, Enabled: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	snapshot := risk.Snapshot{IP: "10.0.0.8", AssessmentLevel: "high", AutomationEligible: true}
	matched, err := manager.apply(context.Background(), &snapshot, "")
	if err != nil {
		t.Fatal(err)
	}
	if matched == nil || snapshot.AssessmentLevel != "benign" || snapshot.AutomationEligible {
		t.Fatalf("exception was not applied: %#v", snapshot)
	}
}

func TestLocalAuthEnforcesSessionCSRFAndViewerPermissions(t *testing.T) {
	dir := t.TempDir()
	hash, err := hashPassword("viewer-password-123")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(localUserFile{Version: 1, Users: []localUser{{ID: "viewer-1", Username: "viewer", Name: "只读用户", Role: "viewer", PasswordHash: hash}}})
	authFile := filepath.Join(dir, "users.json")
	if err := os.WriteFile(authFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithError(Options{ShadowDir: dir, AuthFile: authFile})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	response, err := client.Get(httpServer.URL + "/api/v1/session")
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated session to return 401, status=%v err=%v", response.StatusCode, err)
	}
	_ = response.Body.Close()

	loginBody := bytes.NewBufferString(`{"username":"viewer","password":"viewer-password-123"}`)
	response, err = client.Post(httpServer.URL+"/api/v1/auth/login", "application/json", loginBody)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("login failed: status=%v err=%v", response.StatusCode, err)
	}
	var session Session
	if err := json.NewDecoder(response.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if session.Role != "viewer" || session.CSRFToken == "" || sessionHasPermission(session, "rules:reload") {
		t.Fatalf("unexpected viewer session: %#v", session)
	}

	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/v1/rules/reload", nil)
	request.Header.Set("X-CSRF-Token", session.CSRFToken)
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer write must return 403: status=%v err=%v", response.StatusCode, err)
	}
	_ = response.Body.Close()

	request, _ = http.NewRequest(http.MethodPost, httpServer.URL+"/api/v1/auth/logout", nil)
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without csrf must return 403: status=%v err=%v", response.StatusCode, err)
	}
	_ = response.Body.Close()
}
