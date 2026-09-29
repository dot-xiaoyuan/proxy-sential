package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

func TestPolicyCreateDefaultsAndFilePersistence(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(Options{ShadowDir: dir, ReadOnly: true})
	r := httptest.NewRequest("POST", "/api/v1/policies", bytes.NewBufferString(`{"policy_id":"quota","name":"设备配额","enabled":true,"mode":"automatic","trigger":"quota_exceeded","limits":{"total":2}}`))
	w := httptest.NewRecorder()
	s.handlePolicies(w, r, "/policies")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var p policy.Definition
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Enabled || p.Mode != "observe" {
		t.Fatal(p)
	}
	reopened := NewServer(Options{ShadowDir: dir, ReadOnly: true})
	if reopened.operations.doc.Policies["quota"].Limits.Total == nil {
		t.Fatal("policy not persisted")
	}
	if requiredPermission("POST", "/policy-executions/a/approve") != "policies:authorize" || requiredPermission("POST", "/policy-executions/a/revoke") != "actions:revoke" {
		t.Fatal("permissions not separated")
	}
}
func TestPolicyPartialFailureStopsStages(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.operations.doc.Actions["ok"] = EnforcementAction{Status: "succeeded"}
	s.operations.doc.Actions["bad"] = EnforcementAction{Status: "failed"}
	e := policy.Execution{Stages: []policy.StageState{{ActionIDs: []string{"ok", "bad"}}}}
	s.refreshPolicyStagesLocked(&e, time.Now())
	if e.Stages[0].Status != "partial_success" || !e.Stages[0].CompletedAt.IsZero() {
		t.Fatal(e)
	}
}

func TestAccountFanoutLeaseAndNewSession(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.operations.doc.Connectors["c"] = ActionConnector{ConnectorID: "c", Enabled: true, Mode: "active", ShadowReady: true, ActionMapping: map[string]string{"account_policy_v1": "supported", "session.rate_limit": "limit"}}
	now := time.Now().UTC()
	e := policy.Execution{ID: "execution", AccountID: "a", Definition: policy.Definition{Stages: []policy.Stage{{ConnectorID: "c", Action: "rate_limit", DurationSeconds: 600, RateKbps: 1000}}}, Stages: []policy.StageState{{Key: "lease"}}}
	ss := []policy.Session{{ID: "1", AccountID: "a", IP: "192.0.2.1", CampusID: "c", AccessDomain: "nas", Source: "auth", SensorID: "auth-sensor", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}}
	s.createPolicyActionsLocked(&e, 0, ss, now)
	if len(e.Stages[0].ActionIDs) != 1 {
		t.Fatal(e)
	}
	second := ss[0]
	second.ID = "2"
	second.IP = "192.0.2.2"
	ss = append(ss, second)
	s.createPolicyActionsLocked(&e, 0, ss, now.Add(time.Second))
	if len(e.Stages[0].ActionIDs) != 2 {
		t.Fatal(e)
	}
	s.createPolicyActionsLocked(&e, 0, ss, now.Add(2*time.Second))
	if len(e.Stages[0].ActionIDs) != 2 || len(s.operations.doc.Actions) != 2 {
		t.Fatal("duplicate fanout")
	}
	for _, a := range s.operations.doc.Actions {
		if a.PolicyParameters.LeaseID != "lease" || a.AccountID != "a" || a.DurationSeconds > 600 {
			t.Fatal(a)
		}
	}
	s.releasePolicyActionsLocked(e, now.Add(3*time.Second), "test")
	for _, a := range s.operations.doc.Actions {
		if a.Status != "cancelled" {
			t.Fatal(a)
		}
	}
}

type policySandboxReader struct {
	store.Reader
	sessions []policy.Session
}

func (r policySandboxReader) ListPolicySessions(context.Context, time.Time) ([]policy.Session, error) {
	return r.sessions, nil
}
func TestPolicyControllerSandbox(t *testing.T) {
	now := time.Now().UTC()
	limit := 0
	ss := []policy.Session{{ID: "online", AccountID: "a", EndpointID: "d", IP: "192.0.2.1", CampusID: "c", AccessDomain: "nas", Source: "auth", SensorID: "auth-sensor", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, HeartbeatSeconds: 60}}
	received := 0
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("X-Proxy-Sentinel-Signature") != signActionPayload("test-secret", r.Header.Get("X-Proxy-Sentinel-Timestamp"), raw) {
			t.Error("invalid request signature")
		}
		var body map[string]any
		if err = json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		subject := body["subject"].(map[string]any)
		params := body["policy"].(map[string]any)
		if subject["account_id"] != "a" || params["lease_id"] != "lease" {
			t.Error(body)
		}
		received++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action_id":"remote-1","status":"completed"}`))
	}))
	defer gateway.Close()
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true, ActionMasterKey: "test-master-key-at-least-16"})
	s.reader = policySandboxReader{Reader: s.reader, sessions: ss}
	s.identitySources = []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: "auth", SensorID: "auth-sensor", CampusID: "c", AccessDomain: "nas"}, IntervalSeconds: 60}}
	secret, err := s.encryptConnectorSecret("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	s.operations.doc.Connectors["c"] = ActionConnector{ConnectorID: "c", EndpointURL: gateway.URL, EncryptedSecret: secret, Enabled: true, Mode: "active", ShadowReady: true, ActionMapping: map[string]string{"account_policy_v1": "supported", "account.rate_limit": "limit"}}
	e := policy.Execution{ID: "execution", AccountID: "a", State: "pending_action", Definition: policy.Definition{Trigger: "quota_exceeded", Limits: policy.Limits{Total: &limit}, Stages: []policy.Stage{{ConnectorID: "c", Action: "rate_limit", DurationSeconds: 600, RateKbps: 1000}}}, Stages: []policy.StageState{{Key: "lease"}}}
	s.createPolicyActionsLocked(&e, 0, ss, now)
	e.PolicyID = "quota-sandbox"
	e.Definition.ID = e.PolicyID
	e.Definition.Enabled = true
	e.Definition.Mode = "automatic"
	e.Definition.Revision = 1
	s.operations.doc.Policies[e.PolicyID] = e.Definition
	s.operations.doc.PolicyExecutions[e.ID] = e
	if len(e.Stages[0].ActionIDs) != 1 {
		t.Fatal(e)
	}
	id := e.Stages[0].ActionIDs[0]
	registered := s.identitySources
	s.identitySources = nil
	if err := s.validatePolicyDelivery(s.operations.doc.Actions[id]); err == nil {
		t.Fatal("removed identity authority accepted during execution precheck")
	}
	s.identitySources = registered
	current := s.operations.doc.Policies[e.PolicyID]
	disabled := current
	disabled.Enabled = false
	s.operations.doc.Policies[e.PolicyID] = disabled
	if err := s.validatePolicyDelivery(s.operations.doc.Actions[id]); err == nil {
		t.Fatal("queued quota action ignored disabled policy")
	}
	exempt := current
	exempt.Exempt.Accounts = []string{"a"}
	s.operations.doc.Policies[e.PolicyID] = exempt
	if err := s.validatePolicyDelivery(s.operations.doc.Actions[id]); err == nil {
		t.Fatal("queued quota action ignored account exemption")
	}
	s.operations.doc.Policies[e.PolicyID] = current
	s.deliverAction(id, false)
	s.deliverAction(id, false)
	if received != 1 || s.operations.doc.Actions[id].Status != "succeeded" {
		t.Fatal("duplicate delivery or failed action", received, s.operations.doc.Actions[id])
	}
	s.releasePolicyActionsLocked(e, now, "manual-revoke")
	for id, a := range s.operations.doc.Actions {
		if a.ActionType == "release" {
			s.deliverAction(id, true)
		}
	}
	if received != 2 || s.operations.doc.Actions[id].Status != "revoked" {
		t.Fatal("release failed")
	}
}
