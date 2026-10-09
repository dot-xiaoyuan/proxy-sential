package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestActionRecoveryTemporaryPrecheckKeepsIntentWithoutTransportAttempt(t *testing.T) {
	for _, kind := range []string{"release", "quarantine", "session.disconnect"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := actionReceiptReplay(t)
			a := EnforcementAction{ActionID: "owned-retry", ConnectorID: "owned", IdempotencyKey: "same-key", ActionType: kind, Status: "pending", Mode: "active", AccountID: "fixture", RetryCount: 2}
			s.operations.doc.Actions[a.ActionID] = a
			before := s.operations.doc.Connectors[a.ConnectorID]
			for failure := 1; failure <= 5; failure++ {
				preview := s.operations.doc.Actions[a.ActionID]
				if err := s.recordActionPrecheckFailure(preview, context.DeadlineExceeded); err != nil {
					t.Fatal(err)
				}
				current := s.operations.doc.Actions[a.ActionID]
				if current.PrecheckRetryCount != failure || !current.PrecheckRetryable || current.RetryCount != 2 || current.IdempotencyKey != a.IdempotencyKey || !reflect.DeepEqual(s.operations.doc.Connectors[a.ConnectorID], before) {
					t.Fatalf("precheck failure changed transport or circuit: %+v", current)
				}
				if failure < 5 {
					due, err := time.Parse(time.RFC3339Nano, current.NextAttemptAt)
					if err != nil || !due.After(time.Now()) || current.Status != "pending" {
						t.Fatalf("temporary failure lost scheduled intent: %+v", current)
					}
				} else if current.Status != "blocked" || current.NextAttemptAt != "" {
					t.Fatalf("precheck retries were not bounded: %+v", current)
				}
			}
		})
	}
}

func TestActionRecoveryDefinitiveFailureDoesNotRetry(t *testing.T) {
	for _, cause := range []error{errors.New("evidence expired"), errors.New("global stop"), errors.New("channel is not verified")} {
		t.Run(cause.Error(), func(t *testing.T) {
			s, _ := actionReceiptReplay(t)
			a := EnforcementAction{ActionID: "owned-retry", ConnectorID: "owned", ActionType: "release", Status: "pending", PrecheckRetryCount: 2, PrecheckRetryable: true}
			s.operations.doc.Actions[a.ActionID] = a
			if err := s.recordActionPrecheckFailure(a, cause); err != nil {
				t.Fatal(err)
			}
			current := s.operations.doc.Actions[a.ActionID]
			if current.Status != "blocked" || current.PrecheckRetryable || current.NextAttemptAt != "" || current.PrecheckRetryCount != 2 {
				t.Fatalf("definitive rejection retried: %+v", current)
			}
		})
	}
}

func TestActionRecoveryManualRevokeRetriesExistingTemporaryReleaseOnce(t *testing.T) {
	s, _ := actionReceiptReplay(t)
	s.operations.doc.Connectors["owned"] = ActionConnector{ConnectorID: "owned", Mode: "active", Enabled: true}
	now := time.Now().UTC()
	parent := EnforcementAction{ActionID: "owned-parent", IdempotencyKey: "owned-parent-key", ConnectorID: "owned", Status: "succeeded", Mode: "active", AccountID: "fixture"}
	release := s.newReleaseAction(parent, "system-expiry", now)
	release.Status = "blocked"
	release.PrecheckRetryCount = 5
	release.PrecheckRetryable = true
	release.LastError = "temporary read unavailable"
	s.operations.doc.Actions[parent.ActionID] = parent
	s.operations.doc.Actions[release.ActionID] = release
	w := httptest.NewRecorder()
	s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/actions/"+parent.ActionID+"/revoke", nil), parent.ActionID)
	current := s.operations.doc.Actions[release.ActionID]
	if w.Code != http.StatusAccepted || current.Status != "pending" || current.PrecheckRetryCount != 0 || current.PrecheckRetryable || current.IdempotencyKey != release.IdempotencyKey || len(s.operations.doc.Actions) != 2 {
		t.Fatalf("manual retry did not reuse release: http=%d action=%+v", w.Code, current)
	}
	before := current
	w = httptest.NewRecorder()
	s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/actions/"+parent.ActionID+"/revoke", nil), parent.ActionID)
	if w.Code != http.StatusOK || !reflect.DeepEqual(before, s.operations.doc.Actions[release.ActionID]) || len(s.operations.doc.Actions) != 2 {
		t.Fatal("duplicate revoke reset or duplicated retry")
	}
}

func TestActionRecoveryOldFailureCannotConsumeNewOperatorBudget(t *testing.T) {
	s, _ := actionReceiptReplay(t)
	old := EnforcementAction{ActionID: "owned", ConnectorID: "owned", ActionType: "release", Status: "pending", UpdatedAt: "2026-10-01T00:00:00Z"}
	current := old
	current.UpdatedAt = "2026-10-01T00:00:01Z"
	s.operations.doc.Actions[old.ActionID] = current
	if err := s.recordActionPrecheckFailure(old, context.DeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(current, s.operations.doc.Actions[old.ActionID]) {
		t.Fatal("old timeout consumed a new operator retry budget")
	}
}

func TestActionRecoveryTemporaryErrorClasses(t *testing.T) {
	for _, cause := range []error{context.Canceled, actionPrecheckReadError{cause: errors.New("storage unavailable")}, identityAuthorityUnavailableError{cause: errors.New("registration read failed")}} {
		t.Run(cause.Error(), func(t *testing.T) {
			s, _ := actionReceiptReplay(t)
			a := EnforcementAction{ActionID: "owned", ConnectorID: "owned", Status: "running"}
			s.operations.doc.Actions[a.ActionID] = a
			if err := s.recordActionPrecheckFailure(a, cause); err != nil {
				t.Fatal(err)
			}
			if got := s.operations.doc.Actions[a.ActionID]; got.Status != "pending" || got.PrecheckRetryCount != 1 || !got.PrecheckRetryable {
				t.Fatalf("known temporary class was not retried: %+v", got)
			}
		})
	}
}

func TestActionRecoveryManualRetryRechecksStopAndKeepsSameKey(t *testing.T) {
	s, _ := actionReceiptReplay(t)
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Idempotency-Key") != "parent-key:release" {
			t.Error("manual retry changed recovery key")
		}
		w.Write([]byte(`{"action_id":"recovered","status":"completed"}`))
	}))
	defer remote.Close()
	connector := s.operations.doc.Connectors["owned"]
	connector.Mode = "active"
	connector.Enabled = true
	connector.EndpointURL = remote.URL
	s.operations.doc.Connectors["owned"] = connector
	parent := EnforcementAction{ActionID: "parent", ConnectorID: "owned", IdempotencyKey: "parent-key", AccountID: "fixture", Status: "succeeded", Mode: "active"}
	child := s.newReleaseAction(parent, "manual-revoke", time.Now().UTC())
	child.Status = "blocked"
	s.operations.doc.Actions[parent.ActionID] = parent
	s.operations.doc.Actions[child.ActionID] = child
	request := func() {
		w := httptest.NewRecorder()
		s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/actions/parent/revoke", nil), parent.ActionID)
		if w.Code != http.StatusAccepted {
			t.Fatalf("explicit retry of blocked recovery rejected: %d", w.Code)
		}
		s.deliverAction(child.ActionID, true)
	}
	s.operations.doc.GlobalStop = true
	request()
	if calls.Load() != 0 || s.operations.doc.Actions[child.ActionID].Status != "blocked" {
		t.Fatal("manual retry bypassed stop")
	}
	s.operations.doc.GlobalStop = false
	request()
	if calls.Load() != 1 || s.operations.doc.Actions[parent.ActionID].Status != "revoked" || len(s.operations.doc.Actions) != 2 {
		t.Fatal("explicit retry did not restore the original lease")
	}
}

func TestActionRecoveryManualRetryCannotChangeRecoveryScope(t *testing.T) {
	for _, change := range []string{"account", "evidence", "lease", "shadow", "parent_revoked", "remote_receipt"} {
		t.Run(change, func(t *testing.T) {
			s, _ := actionReceiptReplay(t)
			parent := EnforcementAction{ActionID: "parent", ConnectorID: "owned", IdempotencyKey: "parent-key", AccountID: "fixture", Status: "succeeded", Mode: "active", EvidenceIDs: []string{"approved"}, PolicyParameters: PolicyActionParameters{LeaseID: "original-lease"}}
			child := s.newReleaseAction(parent, "manual-revoke", time.Now().UTC())
			child.Status = "blocked"
			child.PrecheckRetryable = true
			child.PrecheckRetryCount = 5
			switch change {
			case "account":
				child.AccountID = "other"
			case "evidence":
				child.EvidenceIDs = []string{"changed"}
			case "lease":
				child.PolicyParameters.LeaseID = "other-lease"
			case "shadow":
				child.Mode = "shadow"
			case "parent_revoked":
				parent.Status = "revoked"
			case "remote_receipt":
				child.RemoteActionID = "confirmed"
			}
			s.operations.doc.Actions[parent.ActionID] = parent
			s.operations.doc.Actions[child.ActionID] = child
			w := httptest.NewRecorder()
			s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/actions/parent/revoke", nil), parent.ActionID)
			if w.Code != http.StatusOK || !reflect.DeepEqual(child, s.operations.doc.Actions[child.ActionID]) {
				t.Fatal("manual retry changed scope or a finished result")
			}
		})
	}
}

func TestActionRecoveryEarlyQueueWakeupKeepsBackoff(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "native"}[native], func(t *testing.T) {
			s, _ := actionReceiptReplay(t)
			var calls atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Write([]byte(`{"action_id":"must-not-send","status":"completed"}`))
			}))
			defer remote.Close()
			connector := s.operations.doc.Connectors["owned"]
			connector.Mode = "active"
			connector.Enabled = true
			connector.EndpointURL = remote.URL
			s.operations.doc.Connectors["owned"] = connector
			a := EnforcementAction{ActionID: "owned", ConnectorID: "owned", Status: "pending", Mode: "active", PrecheckRetryCount: 1, PrecheckRetryable: true, NextAttemptAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
			if native {
				a.PolicyParameters.NativeSelected = true
			}
			s.operations.doc.Actions[a.ActionID] = a
			s.deliverAction(a.ActionID, false)
			if calls.Load() != 0 || !reflect.DeepEqual(a, s.operations.doc.Actions[a.ActionID]) {
				t.Fatal("early queue wakeup dispatched or changed scheduled intent")
			}
		})
	}
}
