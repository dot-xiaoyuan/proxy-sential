package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func actionReceiptReplay(t *testing.T) (*Server, string) {
	t.Helper()
	ops, err := newOperationsState("", "")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{operations: ops, actionMasterKey: []byte("isolated-receipt-key-123456789012")}
	secret := "isolated-receipt-secret"
	encrypted, err := s.encryptConnectorSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	ops.doc.Connectors["owned"] = ActionConnector{ConnectorID: "owned", EncryptedSecret: encrypted, ConsecutiveFailures: 4, CircuitOpenUntil: "2026-10-01T05:00:00Z"}
	return s, secret
}

func signedReceiptCallback(s *Server, secret string, a EnforcementAction, status, remote, cause string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"action_id": a.ActionID, "status": status, "remote_action_id": remote, "error": cause})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/actions/callback", bytes.NewReader(body))
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	r.Header.Set("X-Proxy-Sentinel-Timestamp", stamp)
	r.Header.Set("X-Proxy-Sentinel-Signature", signActionPayload(secret, stamp, body))
	w := httptest.NewRecorder()
	s.handleActionCallback(w, r)
	return w
}

func TestActionReceiptConflictingCallbackPreservesTerminalResult(t *testing.T) {
	for _, status := range []string{"succeeded", "revoked", "expired", "cancelled", "blocked", "shadow"} {
		t.Run(status, func(t *testing.T) {
			s, secret := actionReceiptReplay(t)
			a := EnforcementAction{ActionID: "owned-action", ConnectorID: "owned", Status: status, AccountID: "fixture", RemoteActionID: "existing-receipt", LastError: "existing result", UpdatedAt: "original timestamp"}
			s.operations.doc.Actions[a.ActionID] = a
			connector := s.operations.doc.Connectors[a.ConnectorID]
			w := signedReceiptCallback(s, secret, a, "failed", "late-receipt", "late failure")
			if w.Code != http.StatusConflict || !reflect.DeepEqual(s.operations.doc.Actions[a.ActionID], a) || !reflect.DeepEqual(s.operations.doc.Connectors[a.ConnectorID], connector) {
				t.Fatalf("conflicting callback changed terminal result: http=%d status=%s failures=%d", w.Code, s.operations.doc.Actions[a.ActionID].Status, s.operations.doc.Connectors[a.ConnectorID].ConsecutiveFailures)
			}
		})
	}
}

func TestActionReceiptDuplicateIsNoopAndDifferentRemoteIsConflict(t *testing.T) {
	s, secret := actionReceiptReplay(t)
	a := EnforcementAction{ActionID: "owned-action", ConnectorID: "owned", Status: "succeeded", RemoteActionID: "receipt-one", UpdatedAt: "original timestamp"}
	s.operations.doc.Actions[a.ActionID] = a
	connector := s.operations.doc.Connectors[a.ConnectorID]
	for _, remote := range []string{"receipt-one", "receipt-two"} {
		w := signedReceiptCallback(s, secret, a, "succeeded", remote, "")
		want := http.StatusOK
		if remote != a.RemoteActionID {
			want = http.StatusConflict
		}
		if w.Code != want || !reflect.DeepEqual(s.operations.doc.Actions[a.ActionID], a) || !reflect.DeepEqual(s.operations.doc.Connectors[a.ConnectorID], connector) {
			t.Fatalf("duplicate/conflicting remote modified result: remote=%s http=%d", remote, w.Code)
		}
	}
}

func TestActionReceiptConfirmedSuccessCanResolveFailedTransport(t *testing.T) {
	s, secret := actionReceiptReplay(t)
	a := EnforcementAction{ActionID: "owned-action", ConnectorID: "owned", Status: "failed", LastError: "transport exhausted"}
	s.operations.doc.Actions[a.ActionID] = a
	w := signedReceiptCallback(s, secret, a, "succeeded", "confirmed-receipt", "")
	if w.Code != http.StatusOK || s.operations.doc.Actions[a.ActionID].Status != "succeeded" || s.operations.doc.Connectors[a.ConnectorID].ConsecutiveFailures != 0 {
		t.Fatalf("confirmed completion did not resolve transport failure: http=%d", w.Code)
	}
}

func TestActionReceiptLateHTTPDoesNotOverwriteChangedResultOrAttempt(t *testing.T) {
	for _, response := range []string{"completed", "failed"} {
		for _, change := range []string{"revoked", "cancelled", "retry", "account", "recovered_lease"} {
			t.Run(response+"/"+change, func(t *testing.T) {
				s, _ := actionReceiptReplay(t)
				a := EnforcementAction{ActionID: "owned-action", ConnectorID: "owned", Status: "running", AccountID: "fixture", IdempotencyKey: "owned", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				s.operations.doc.Actions[a.ActionID] = a
				var updated EnforcementAction
				connector := s.operations.doc.Connectors[a.ConnectorID]
				remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					s.operations.mu.Lock()
					updated = s.operations.doc.Actions[a.ActionID]
					switch change {
					case "revoked", "cancelled":
						updated.Status = change
						updated.LastError = "new result"
					case "retry":
						updated.RetryCount++
					case "account":
						updated.AccountID = "different-account"
					case "recovered_lease":
						updated.UpdatedAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
					}
					s.operations.doc.Actions[a.ActionID] = updated
					s.operations.mu.Unlock()
					if response == "completed" {
						w.Write([]byte(`{"action_id":"late-success","status":"completed"}`))
					} else {
						http.Error(w, "late failure", http.StatusServiceUnavailable)
					}
				}))
				defer remote.Close()
				connector.EndpointURL = remote.URL
				s.deliverActionRequest(a, connector, false)
				if !reflect.DeepEqual(s.operations.doc.Actions[a.ActionID], updated) || !reflect.DeepEqual(s.operations.doc.Connectors[a.ConnectorID], connectorWithoutEndpoint(connector)) {
					t.Fatalf("late transport changed newer result/attempt: change=%s status=%s", change, s.operations.doc.Actions[a.ActionID].Status)
				}
			})
		}
	}
}

func TestActionReceiptCurrentAttemptStillRetriesAndCompletes(t *testing.T) {
	s, _ := actionReceiptReplay(t)
	a := EnforcementAction{ActionID: "owned-action", ConnectorID: "owned", Status: "running", AccountID: "fixture", UpdatedAt: "2026-10-01T03:00:00.123456789Z"}
	stored := a
	stored.UpdatedAt = "2026-10-01T03:00:00.123457Z"
	s.operations.doc.Actions[a.ActionID] = stored
	if err := s.scheduleActionRetryForAttempt(a, "transport failure"); err != nil {
		t.Fatal(err)
	}
	current := s.operations.doc.Actions[a.ActionID]
	if current.Status != "pending" || current.RetryCount != 1 || current.NextAttemptAt == "" {
		t.Fatal("current failure did not schedule retry")
	}
	current.Status = "running"
	s.operations.doc.Actions[a.ActionID] = current
	if err := s.finishActionReceipt(current, "succeeded", "current-receipt", ""); err != nil {
		t.Fatal(err)
	}
	if s.operations.doc.Actions[a.ActionID].Status != "succeeded" {
		t.Fatal("current completion not applied")
	}
}

func connectorWithoutEndpoint(c ActionConnector) ActionConnector { c.EndpointURL = ""; return c }
