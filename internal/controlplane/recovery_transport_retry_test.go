package controlplane

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestRecoveryTransportExplicitRetryPreservesExhaustedBudget(t *testing.T) {
	s, _ := actionReceiptReplay(t)
	s.operations.doc.Connectors["owned"] = ActionConnector{ConnectorID: "owned", Mode: "active", Enabled: true, ConsecutiveFailures: 2}
	parent := EnforcementAction{ActionID: "owned-parent", IdempotencyKey: "owned-parent-key", ConnectorID: "owned", Status: "succeeded", Mode: "active", AccountID: "owned-account", PolicyParameters: PolicyActionParameters{LeaseID: "owned-original-lease"}}
	child := s.newReleaseAction(parent, "system-expiry", time.Now().UTC())
	child.Status = "failed"
	child.RetryCount = 3
	child.LastError = "transport retry exhausted"
	s.operations.doc.Actions[parent.ActionID] = parent
	s.operations.doc.Actions[child.ActionID] = child
	connector := s.operations.doc.Connectors[child.ConnectorID]
	w := httptest.NewRecorder()
	s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/revoke", nil), parent.ActionID)
	current := s.operations.doc.Actions[child.ActionID]
	if w.Code != http.StatusAccepted || current.Status != "pending" || current.RetryCount != 3 || current.IdempotencyKey != child.IdempotencyKey || current.PolicyParameters.LeaseID != child.PolicyParameters.LeaseID || current.CreatedBy != child.CreatedBy || !reflect.DeepEqual(s.operations.doc.Connectors[child.ConnectorID], connector) || len(s.operations.doc.Actions) != 2 {
		t.Fatal("explicit recovery retry reset transport accounting, scope, circuit, or lineage")
	}
	w = httptest.NewRecorder()
	s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/revoke", nil), parent.ActionID)
	if w.Code != http.StatusOK || !reflect.DeepEqual(current, s.operations.doc.Actions[child.ActionID]) {
		t.Fatal("duplicate revoke reset the already queued recovery")
	}
	// An old result from the exhausted attempt cannot consume the operator's
	// new generation, and a genuine new failure must stop automatic retry.
	if err := s.scheduleActionRetryForAttempt(child, "old timeout"); err == nil || !reflect.DeepEqual(current, s.operations.doc.Actions[child.ActionID]) {
		t.Fatal("old exhausted attempt altered the new manual generation")
	}
	if err := s.scheduleActionRetryForAttempt(current, "new timeout"); err != nil {
		t.Fatal(err)
	}
	current = s.operations.doc.Actions[child.ActionID]
	if current.Status != "failed" || current.RetryCount != 4 || current.NextAttemptAt != "" {
		t.Fatal("manual recovery retry acquired a fresh automatic transport budget")
	}
}

func TestRecoveryTransportExplicitRetryKeepsScopeAndDefinitiveFailure(t *testing.T) {
	for _, changed := range []string{"not_exhausted", "nontransport_failure", "account", "lease", "evidence", "remote_receipt", "shadow", "native_connector", "parent_restored"} {
		t.Run(changed, func(t *testing.T) {
			s, _ := actionReceiptReplay(t)
			s.operations.doc.Connectors["owned"] = ActionConnector{ConnectorID: "owned", Mode: "active", Enabled: true}
			parent := EnforcementAction{ActionID: "parent", IdempotencyKey: "parent-key", ConnectorID: "owned", AccountID: "owned-account", Status: "succeeded", Mode: "active", PolicyParameters: PolicyActionParameters{LeaseID: "original-lease"}}
			child := s.newReleaseAction(parent, "manual-revoke", time.Now().UTC())
			child.Status, child.RetryCount = "failed", 3
			switch changed {
			case "not_exhausted":
				child.RetryCount = 2
			case "nontransport_failure":
				child.RetryCount = 0
			case "account":
				child.AccountID = "other-account"
			case "lease":
				child.PolicyParameters.LeaseID = "other-lease"
			case "evidence":
				child.EvidenceIDs = []string{"other-evidence"}
			case "remote_receipt":
				child.RemoteActionID = "known-receipt"
			case "shadow":
				child.Mode = "shadow"
			case "native_connector":
				connector := s.operations.doc.Connectors["owned"]
				connector.ConnectorType = "srun4k"
				s.operations.doc.Connectors["owned"] = connector
			case "parent_restored":
				parent.Status = "revoked"
			}
			s.operations.doc.Actions[parent.ActionID] = parent
			s.operations.doc.Actions[child.ActionID] = child
			w := httptest.NewRecorder()
			s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/revoke", nil), parent.ActionID)
			if w.Code != http.StatusOK || !reflect.DeepEqual(s.operations.doc.Actions[child.ActionID], child) || len(s.operations.doc.Actions) != 2 {
				t.Fatal("explicit retry changed a definitive failure or a different recovery scope")
			}
		})
	}
}
