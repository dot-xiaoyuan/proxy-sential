package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestPostgresOperationsRepositoryPersistsAcrossInstances(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	first, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	evidence := store.ProxyReviewCase{CaseID: "integration-evidence", IP: "192.0.2.10", RiskScore: 95}
	firstSnapshot := newCaseEvidenceSnapshot("integration-case", "integration-rules-v1", evidence, time.Now().UTC().Add(-time.Minute))
	evidence.RiskScore = 97
	secondSnapshot := newCaseEvidenceSnapshot("integration-case", "integration-rules-v1", evidence, time.Now().UTC())
	first.mu.Lock()
	first.doc.Campuses["integration-campus"] = Campus{CampusID: "integration-campus", Code: "IT", Name: "集成测试校区", Enabled: true}
	first.doc.Cases["integration-case"] = RiskCase{CaseID: "integration-case", DedupeKey: "integration-dedupe", SubjectType: "ip", SubjectID: "192.0.2.10", IP: "192.0.2.10", Status: "new", Priority: "high", RiskScore: 95, RiskConfidence: .95, AssessmentLevel: "high", RulesetVersion: "integration-rules-v1", EvidenceSnapshot: firstSnapshot.Evidence, EvidenceHistory: []CaseEvidenceSnapshot{firstSnapshot, secondSnapshot}, FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now}
	first.doc.Connectors["integration-connector"] = ActionConnector{ConnectorID: "integration-connector", Name: "集成连接器", EndpointURL: "https://northbound.example.test/actions", ActionMapping: map[string]string{"disconnect": "kick"}, Mode: "active", Enabled: true, ShadowReady: true, CircuitOpenUntil: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), ConsecutiveFailures: 2, ShadowStartedAt: time.Now().UTC().Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano), ShadowValidationSince: time.Now().UTC().Add(-9 * 24 * time.Hour).Format(time.RFC3339Nano), ShadowCandidateCount: 20, ShadowReviewedCount: 20, ShadowAccuracy: 1, EncryptedSecret: "encrypted", UpdatedAt: now}
	first.doc.Actions["integration-action"] = EnforcementAction{ActionID: "integration-action", IdempotencyKey: "integration-action-key", CaseID: "integration-case", ConnectorID: "integration-connector", ActionType: "disconnect", SubjectType: "account", SubjectID: "student-integration", AccountID: "student-integration", EndpointID: "endpoint-integration", SessionID: "session-integration", CampusID: "integration-campus", Status: "pending", Mode: "active", EvidenceIDs: []string{"evidence-integration"}, RulesetVersion: "integration-rules-v1", RetryCount: 1, NextAttemptAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), CreatedBy: "integration", CreatedAt: now, UpdatedAt: now}
	if err := first.saveLocked(); err != nil {
		first.mu.Unlock()
		t.Fatal(err)
	}
	first.mu.Unlock()
	(&Server{operations: first}).recordActionAttempt(first.doc.Actions["integration-action"], []byte(`{"action":"disconnect"}`), []byte(`{"accepted":true}`), http.StatusAccepted, "")

	second, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	second.mu.Lock()
	defer second.mu.Unlock()
	if second.doc.Campuses["integration-campus"].Name != "集成测试校区" {
		t.Fatalf("campus was not persisted: %#v", second.doc.Campuses)
	}
	if second.doc.Cases["integration-case"].RiskScore != 95 {
		t.Fatalf("case was not persisted: %#v", second.doc.Cases)
	}
	persisted := second.doc.Cases["integration-case"]
	if len(persisted.EvidenceHistory) != 2 || persisted.EvidenceHistory[0].SnapshotID != firstSnapshot.SnapshotID || persisted.EvidenceHistory[1].SnapshotID != secondSnapshot.SnapshotID {
		t.Fatalf("case evidence history was not persisted in order: %#v", persisted.EvidenceHistory)
	}
	if persisted.EvidenceSnapshot.RiskScore != firstSnapshot.Evidence.RiskScore {
		t.Fatalf("initial evidence snapshot was not kept immutable: %#v", persisted.EvidenceSnapshot)
	}
	connector := second.doc.Connectors["integration-connector"]
	if connector.ConsecutiveFailures != 2 || connector.ShadowCandidateCount != 20 || connector.ShadowAccuracy != 1 || connector.CircuitOpenUntil == "" || connector.ShadowValidationSince == "" {
		t.Fatalf("connector safety state was not persisted: %+v", connector)
	}
	action := second.doc.Actions["integration-action"]
	if action.SessionID != "session-integration" || action.RulesetVersion != "integration-rules-v1" || action.NextAttemptAt == "" || action.RetryCount != 1 {
		t.Fatalf("durable action retry state was not persisted: %+v", action)
	}
	var attemptCount int
	if err := second.db.QueryRowContext(ctx, `SELECT count(*) FROM enforcement_action_attempts WHERE action_id='integration-action'`).Scan(&attemptCount); err != nil || attemptCount == 0 {
		t.Fatalf("action attempt was not persisted: count=%d err=%v", attemptCount, err)
	}
}

func TestPostgresAuthenticationSessionWorksAcrossInstances(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	username := "admin-" + shortToken(5)
	if err := BootstrapAdminPostgres(dsn, username, "集成测试管理员", "integration-password-123"); err != nil {
		t.Fatal(err)
	}
	first, err := newAuthManager("", true, dsn)
	if err != nil {
		t.Fatal(err)
	}
	token, session, err := first.login("192.0.2.1:1234", username, "integration-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if session.User.Role != "admin" || session.CSRFToken == "" {
		t.Fatalf("unexpected login session: %#v", session)
	}
	second, err := newAuthManager("", true, dsn)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/api/v1/session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	restored, ok := second.current(request)
	if !ok || restored.User.ID != session.User.ID || restored.CSRFToken != session.CSRFToken {
		t.Fatalf("session was not restored across instances: %#v", restored)
	}
}

func TestPostgresUserLifecyclePersists(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	manager, err := newAuthManager("", false, dsn)
	if err != nil {
		t.Fatal(err)
	}
	username := "reviewer-" + shortToken(5)
	created, err := manager.createUser(ctx, userMutation{Username: username, Name: "数据库复核员", Role: "reviewer", Password: "reviewer-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.updateUser(ctx, created.ID, "disable", userMutation{}); err != nil {
		t.Fatal(err)
	}
	second, err := newAuthManager("", false, dsn)
	if err != nil {
		t.Fatal(err)
	}
	items, err := second.listUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		if item.ID == created.ID {
			found = item.Disabled
		}
	}
	if !found {
		t.Fatalf("disabled PostgreSQL user was not persisted: %#v", items)
	}
}
