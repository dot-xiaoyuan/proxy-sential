package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/store"
	"strings"
	"testing"
	"time"
)

type proxyReplayReader struct {
	store.Reader
	sessions []policy.Session
	events   []normalized.Event
}

func (r *proxyReplayReader) ListPolicySessions(context.Context, time.Time) ([]policy.Session, error) {
	return r.sessions, nil
}
func (r *proxyReplayReader) ScanProxyEvents(_ context.Context, q proxyprotocol.Scan) ([]normalized.Event, error) {
	out := []normalized.Event{}
	for _, e := range r.events {
		t, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
		if !t.Before(q.From) && t.Before(q.To) && (q.After.EventID == "" || proxyprotocol.CursorLess(q.After, proxyprotocol.EventCursor(e))) {
			out = append(out, e)
		}
	}
	return out, nil
}
func TestProxyManualPolicySandbox(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	requestAt := now.Add(-time.Minute)
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true, ActionMasterKey: "test-master-key-at-least-16"})
	producer := proxyprotocol.Producer{SensorID: "sensor", Source: "zeek", InstanceID: "boot", ParserID: "sentinel-zeek-proxy", ParserVersion: "1", CampusID: "campus", AccessDomain: "nas", Key: "01234567890123456789012345678901"}
	s.proxyConfig = proxyprotocol.Config{Version: "test-v1", Producers: []proxyprotocol.Producer{producer}}
	e := normalized.Event{EventID: "event", Type: "proxy_transaction", Source: "zeek", Timestamp: requestAt.Add(time.Second).Format(time.RFC3339Nano), Subject: map[string]any{"ip": "192.0.2.1"}, Observer: map[string]any{"sensor_id": "sensor", "collector_instance_id": "boot"}, Flow: map[string]any{"connection_id": "conn"}, Payload: map[string]any{"protocol": "socks5", "transaction_id": "1", "version": 5, "command": 1, "reply": 0, "request_at": requestAt.Format(time.RFC3339Nano), "response_at": requestAt.Add(time.Second).Format(time.RFC3339Nano)}}
	proxyprotocol.Sign(&e, producer)
	reader := &proxyReplayReader{Reader: s.reader, events: []normalized.Event{e}, sessions: []policy.Session{{ID: "session", AccountID: "a", EndpointID: "d", Source: "auth", SensorID: "auth-sensor", CampusID: "campus", AccessDomain: "nas", IP: "192.0.2.1", StartedAt: requestAt.Add(-time.Minute), ConfirmedAt: now, Confirmations: []time.Time{requestAt, now}, HeartbeatSeconds: 60}}}
	s.reader = reader
	s.identitySources = []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: "auth", SensorID: "auth-sensor", CampusID: "campus", AccessDomain: "nas"}, IntervalSeconds: 60}}
	if _, err := s.processProxyProtocol(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	sent := 0
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action_id":"remote","status":"completed"}`))
	}))
	defer gateway.Close()
	secret, err := s.encryptConnectorSecret("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	s.operations.doc.Connectors["c"] = ActionConnector{ConnectorID: "c", Enabled: true, Mode: "active", ShadowReady: true, EncryptedSecret: secret, EndpointURL: gateway.URL, ActionMapping: map[string]string{"account_policy_v1": "supported", "account.disconnect": "disconnect"}}
	p := policy.Definition{ID: "p", Name: "manual proxy", Enabled: true, Mode: "manual", Trigger: "explicit_proxy", Revision: 1, WindowSeconds: 3600, Stages: []policy.Stage{{Action: "disconnect", ConnectorID: "c"}}}
	s.operations.doc.Policies[p.ID] = p
	s.processAccountPolicies(now)
	id := policy.StableID("p", "a")
	ex := s.operations.doc.PolicyExecutions[id]
	if ex.State != "awaiting_approval" || len(s.operations.doc.Actions) != 0 {
		t.Fatal("manual gate bypassed", ex)
	}
	if err = s.validatePolicyDelivery(EnforcementAction{EvidenceIDs: ex.EvidenceIDs}); err == nil {
		t.Fatal("legacy action bypass")
	}
	preview, err := buildPolicyApprovalPreview(ex, reader.sessions, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"fingerprint":"stale"}`} {
		rejected := httptest.NewRecorder()
		s.handlePolicyExecutionMutation(rejected, httptest.NewRequest("POST", "/", strings.NewReader(body)), "/policy-executions/"+id+"/approve")
		if rejected.Code != 409 || s.operations.doc.PolicyExecutions[id].State != "awaiting_approval" {
			t.Fatal("stale confirmation mutated execution", rejected.Code)
		}
	}
	w := httptest.NewRecorder()
	s.handlePolicyExecutionMutation(w, httptest.NewRequest("POST", "/", strings.NewReader(approvalJSON(map[string]string{"fingerprint": preview.Fingerprint}))), "/policy-executions/"+id+"/approve")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s.processAccountPolicies(now.Add(time.Second))
	ex = s.operations.doc.PolicyExecutions[id]
	if len(ex.Stages[0].ActionIDs) != 1 {
		t.Fatal(ex)
	}
	action := s.operations.doc.Actions[ex.Stages[0].ActionIDs[0]]
	reader.sessions[0].AccountID = "rebound"
	if err = s.validatePolicyDelivery(action); err == nil {
		t.Fatal("changed identity permitted")
	}
	reader.sessions[0].AccountID = "a"
	s.deliverAction(action.ActionID, false)
	s.deliverAction(action.ActionID, false)
	if sent != 1 || s.operations.doc.Actions[action.ActionID].Status != "succeeded" {
		t.Fatal(sent, s.operations.doc.Actions[action.ActionID])
	}
	p.Mode = "automatic"
	if err = p.Validate(); err == nil {
		t.Fatal("automatic proxy policy accepted")
	}
	ex.Definition.Mode = "automatic"
	s.operations.doc.PolicyExecutions[id] = ex
	if err = s.validatePolicyDelivery(action); err == nil {
		t.Fatal("persisted automatic policy bypass")
	}
}
