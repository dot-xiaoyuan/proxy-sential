package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func TestActiveActionSignsRequestPersistsSessionAndCreatesReversal(t *testing.T) {
	secret := "northbound-test-secret"
	received := make(chan map[string]any, 4)
	northbound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		timestamp := r.Header.Get("X-Proxy-Sentinel-Timestamp")
		if r.Header.Get("X-Proxy-Sentinel-Signature") != signActionPayload(secret, timestamp, body) || r.Header.Get("Idempotency-Key") == "" {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		received <- payload
		_ = json.NewEncoder(w).Encode(map[string]any{"action_id": "remote-1", "status": "completed"})
	}))
	defer northbound.Close()

	dir := t.TempDir()
	now := time.Now().UTC()
	mac, ip := "a8:bb:cc:dd:ee:09", "10.0.0.9"
	snapshot := riskSnapshot(ip, "high", 96, now.Format(time.RFC3339Nano))
	snapshot.Confidence, snapshot.AccountID, snapshot.EndpointID, snapshot.EvidenceIDs = .96, "student-9", "mac:"+mac, []string{"strong-active"}
	strong := evidenceItem("strong-active", ip, "vpn_proxy_rule_match", now.Format(time.RFC3339Nano))
	strong.Confidence = .96
	writeRun(t, dir, "active-action-run", testRun{startedAt: now.Format(time.RFC3339Nano), risks: []risk.Snapshot{snapshot}, evidence: []evidence.Evidence{strong}, events: []normalized.Event{identityEvent("identity-active", "student-9", ip, mac, "ap-9", "session-9", now.Format(time.RFC3339Nano))}})
	server := NewServer(Options{ShadowDir: dir, OperationsFile: filepath.Join(dir, "operations.json"), ActionMasterKey: "0123456789abcdef0123456789abcdef"})
	encrypted, err := server.encryptConnectorSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	server.operations.doc.Connectors["active"] = ActionConnector{ConnectorID: "active", Name: "active", EndpointURL: northbound.URL, Mode: "active", Enabled: true, ShadowReady: true, EncryptedSecret: encrypted}
	server.operations.doc.Cases["case-active"] = RiskCase{CaseID: "case-active", IP: ip, AccountID: "student-9", EndpointID: "mac:" + mac, CampusID: "main", AuthSessionID: "session-9", RulesetVersion: "rules-v9", Status: "investigating"}
	server.operations.doc.Cases["case-shadow-validation"] = RiskCase{CaseID: "case-shadow-validation", Disposition: "confirmed_proxy"}
	server.operations.doc.Actions["shadow-validation"] = EnforcementAction{ActionID: "shadow-validation", CaseID: "case-shadow-validation", ConnectorID: "active", Mode: "shadow", Status: "shadow", CreatedAt: now.Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano)}
	connectivity := httptest.NewRequest(http.MethodPost, "/api/v1/actions/connectors/active/test", strings.NewReader(`{}`))
	connectivityRecorder := httptest.NewRecorder()
	server.handleConnectorTest(connectivityRecorder, connectivity, "active")
	var connectivityResult map[string]any
	decodeResponse(t, connectivityRecorder, http.StatusOK, &connectivityResult)
	if connectivityPayload := <-received; connectivityPayload["type"] != "connectivity_test" {
		t.Fatalf("unexpected connectivity payload: %#v", connectivityPayload)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/actions/execute", strings.NewReader(`{"case_id":"case-active","connector_id":"active","action_type":"disconnect","ip":"10.0.0.9","duration_seconds":60}`))
	request.Header.Set("Idempotency-Key", "active-key-1")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var action EnforcementAction
	decodeResponse(t, recorder, http.StatusAccepted, &action)
	waitActionStatus(t, server, action.ActionID, "succeeded")
	var detail EnforcementAction
	getJSON(t, server, "/api/v1/actions/"+action.ActionID, http.StatusOK, &detail)
	if detail.RemoteActionID != "remote-1" {
		t.Fatalf("action detail did not expose the remote result: %+v", detail)
	}
	payload := <-received
	subject := payload["subject"].(map[string]any)
	if subject["session_id"] != "session-9" || payload["ruleset_version"] != "rules-v9" {
		t.Fatalf("northbound payload is missing session or ruleset: %#v", payload)
	}
	cooldownRequest := httptest.NewRequest(http.MethodPost, "/api/v1/actions/execute", strings.NewReader(`{"case_id":"case-active","connector_id":"active","action_type":"disconnect","ip":"10.0.0.9"}`))
	cooldownRequest.Header.Set("Idempotency-Key", "active-key-cooldown")
	cooldownRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(cooldownRecorder, cooldownRequest)
	var cooldownAction EnforcementAction
	decodeResponse(t, cooldownRecorder, http.StatusAccepted, &cooldownAction)
	if cooldownAction.Status != "blocked" || !containsString(cooldownAction.Blockers, "subject_cooldown_active") {
		t.Fatalf("subject cooldown did not block repeated punishment: %+v", cooldownAction)
	}

	revoke := httptest.NewRequest(http.MethodPost, "/api/v1/actions/"+action.ActionID+"/revoke", strings.NewReader(`{}`))
	revokeRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(revokeRecorder, revoke)
	var reversal EnforcementAction
	decodeResponse(t, revokeRecorder, http.StatusAccepted, &reversal)
	if reversal.ParentActionID != action.ActionID || reversal.ActionType != "release" || reversal.IdempotencyKey == action.IdempotencyKey {
		t.Fatalf("reversal was not independently persisted: %+v", reversal)
	}
	waitActionStatus(t, server, action.ActionID, "revoked")
	if releasePayload := <-received; releasePayload["action"] != "release" || releasePayload["revoke"] != true {
		t.Fatalf("unexpected release payload: %#v", releasePayload)
	}

	expiredParent := action
	expiredParent.ActionID, expiredParent.IdempotencyKey, expiredParent.Status, expiredParent.CreatedBy = "action-expiring", "active-key-expiring", "succeeded", "operator"
	expiredParent.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	server.operations.doc.Actions[expiredParent.ActionID] = expiredParent
	server.processDueActions(now)
	waitActionStatus(t, server, expiredParent.ActionID, "expired")
	if expiryPayload := <-received; expiryPayload["action"] != "release" {
		t.Fatalf("unexpected automatic expiry payload: %#v", expiryPayload)
	}
}

func containsString(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func TestActionCallbackRequiresFreshHMACAndIsIdempotent(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), OperationsFile: filepath.Join(t.TempDir(), "operations.json"), ActionMasterKey: "0123456789abcdef0123456789abcdef"})
	secret := "callback-secret"
	encrypted, err := server.encryptConnectorSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	server.operations.doc.Connectors["callback"] = ActionConnector{ConnectorID: "callback", EncryptedSecret: encrypted}
	server.operations.doc.Actions["callback-action"] = EnforcementAction{ActionID: "callback-action", ConnectorID: "callback", Status: "running", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	body := []byte(`{"action_id":"callback-action","status":"succeeded","remote_action_id":"remote-callback"}`)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/actions/callback", strings.NewReader(string(body)))
	request.Header.Set("X-Proxy-Sentinel-Timestamp", timestamp)
	request.Header.Set("X-Proxy-Sentinel-Signature", signActionPayload(secret, timestamp, body))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var result map[string]any
	decodeResponse(t, recorder, http.StatusOK, &result)
	if action := server.operations.doc.Actions["callback-action"]; action.Status != "succeeded" || action.RemoteActionID != "remote-callback" {
		t.Fatalf("callback result was not applied: %+v", action)
	}

	stale := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/actions/callback", strings.NewReader(string(body)))
	request.Header.Set("X-Proxy-Sentinel-Timestamp", stale)
	request.Header.Set("X-Proxy-Sentinel-Signature", signActionPayload(secret, stale, body))
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("stale callback must be rejected, got %d", recorder.Code)
	}
}

func TestShadowReadinessCannotBeSelfDeclaredAndCircuitPersists(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), OperationsFile: filepath.Join(t.TempDir(), "operations.json")})
	now := time.Now().UTC()
	connector := ActionConnector{ConnectorID: "gateway", Mode: "shadow", ShadowReady: true}
	server.operations.doc.Cases["case-1"] = RiskCase{CaseID: "case-1", Disposition: "confirmed_proxy"}
	server.operations.doc.Actions["shadow-1"] = EnforcementAction{ActionID: "shadow-1", CaseID: "case-1", ConnectorID: "gateway", Mode: "shadow", Status: "shadow", CreatedAt: now.Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano)}
	server.refreshConnectorShadowReadinessLocked(&connector, now)
	if !connector.ShadowReady || connector.ShadowAccuracy != 1 {
		t.Fatalf("reviewed seven-day shadow evidence should pass: %+v", connector)
	}
	server.operations.doc.Cases["case-1"] = RiskCase{CaseID: "case-1", Disposition: "false_positive"}
	server.refreshConnectorShadowReadinessLocked(&connector, now)
	if connector.ShadowReady {
		t.Fatalf("false-positive shadow action must close the gate: %+v", connector)
	}
	connector.ShadowReady = true
	connector.EndpointURL = "https://old.example.test/actions"
	connector.Name, connector.ActionMapping, connector.EncryptedSecret, connector.UpdatedAt = "gateway", map[string]string{"disconnect": "kick"}, "encrypted", now.Format(time.RFC3339Nano)
	server.operations.doc.Connectors["gateway"] = connector
	request := httptest.NewRequest(http.MethodPost, "/api/v1/actions/connectors", strings.NewReader(`{"connector_id":"gateway","name":"gateway","endpoint_url":"https://new.example.test/actions","action_mapping":{"disconnect":"disconnect"},"mode":"shadow","enabled":true}`))
	recorder := httptest.NewRecorder()
	server.handleConnectors(recorder, request)
	var changed ActionConnector
	decodeResponse(t, recorder, http.StatusOK, &changed)
	if changed.ShadowReady || changed.ShadowValidationSince == "" || changed.ShadowCandidateCount != 0 {
		t.Fatalf("material connector changes must reset shadow validation: %+v", changed)
	}

	server.operations.doc.Connectors["gateway"] = ActionConnector{ConnectorID: "gateway"}
	for index := 0; index < 5; index++ {
		id := "failed-" + string(rune('a'+index))
		server.operations.doc.Actions[id] = EnforcementAction{ActionID: id, ConnectorID: "gateway", Status: "pending"}
		server.scheduleActionRetry(id, "failed")
		server.scheduleActionRetry(id, "failed")
		server.scheduleActionRetry(id, "failed")
	}
	if server.operations.doc.Connectors["gateway"].CircuitOpenUntil == "" {
		t.Fatal("five terminal connector failures must open the circuit")
	}
}

func waitActionStatus(t *testing.T, server *Server, actionID, expected string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		server.operations.mu.Lock()
		status := server.operations.doc.Actions[actionID].Status
		server.operations.mu.Unlock()
		if status == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("action %s did not reach %s", actionID, expected)
}

func TestTransportSuccessRequiresCompletionReceipt(t *testing.T) {
	for _, body := range []string{`{"action_id":"remote","status":"pending"}`, `{"code":10503}`, `{"action_id":"remote"}`, `<html>login</html>`, `{"action_id":"remote","status":"completed"}`} {
		t.Run(body, func(t *testing.T) {
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body == `{"action_id":"remote","status":"completed"}` {
					// Valid JSON prefix, but the declared HTTP body was not delivered.
					w.Header().Set("Content-Length", "999")
				}
				io.WriteString(w, body)
			}))
			defer remote.Close()
			s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true, ActionMasterKey: "0123456789abcdef0123456789abcdef"})
			secret, err := s.encryptConnectorSecret("test")
			if err != nil {
				t.Fatal(err)
			}
			s.operations.doc.Connectors["lab"] = ActionConnector{ConnectorID: "lab", Enabled: true, Mode: "active", EndpointURL: remote.URL, EncryptedSecret: secret}
			s.operations.doc.Actions["action"] = EnforcementAction{ActionID: "action", ConnectorID: "lab", Status: "pending", ActionType: "notify", IdempotencyKey: "stable-key"}
			s.deliverAction("action", false)
			got := s.operations.doc.Actions["action"]
			if got.Status == "succeeded" || got.Status == "revoked" || got.RetryCount != 1 || got.LastError == "" {
				t.Fatal("unconfirmed action completed", got)
			}
		})
	}
}
