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

	"proxy-sentinel/internal/evidence"
)

func TestActionFailurePreservesNewerTerminalState(t *testing.T) {
	for _, phase := range []string{"pending", "running"} {
		for _, state := range []string{"succeeded", "revoked", "cancelled", "failed"} {
			t.Run(phase+"/"+state, func(t *testing.T) {
				ops, err := newOperationsState("", "")
				if err != nil {
					t.Fatal(err)
				}
				s := &Server{operations: ops}
				preview := EnforcementAction{ActionID: "owned", Status: phase, AccountID: "fixture"}
				current := preview
				current.Status = state
				current.RemoteActionID = "completed-receipt"
				current.LastError = "new result"
				ops.doc.Actions[preview.ActionID] = current
				if err := s.recordActionPrecheckFailure(preview, context.DeadlineExceeded); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(ops.doc.Actions[preview.ActionID], current) {
					t.Fatal("old validation overwrote a newer terminal result")
				}
			})
		}
	}
}

func TestActionFailureRejectsChangedIntentOrAttempt(t *testing.T) {
	for _, field := range []string{"account", "evidence", "retry", "remote"} {
		t.Run(field, func(t *testing.T) {
			ops, err := newOperationsState("", "")
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{operations: ops}
			preview := EnforcementAction{ActionID: "owned", Status: "pending", AccountID: "fixture", EvidenceIDs: []string{"approved"}}
			current := preview
			switch field {
			case "account":
				current.AccountID = "changed"
			case "evidence":
				current.EvidenceIDs = []string{"new-proof"}
			case "retry":
				current.RetryCount++
			case "remote":
				current.RemoteActionID = "accepted-receipt"
			}
			ops.doc.Actions[preview.ActionID] = current
			if err := s.recordActionPrecheckFailure(preview, errors.New("old failure")); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ops.doc.Actions[preview.ActionID], current) {
				t.Fatal("old validation mutated changed intent or attempt")
			}
		})
	}
}

func TestActionFailureBlocksCurrentUnsentPhase(t *testing.T) {
	for _, phase := range []string{"pending", "running"} {
		t.Run(phase, func(t *testing.T) {
			ops, err := newOperationsState("", "")
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{operations: ops}
			preview := EnforcementAction{ActionID: "owned", Status: phase, AccountID: "fixture", ExpiresAt: "2026-10-01T03:00:00.123456789Z"}
			preview.UpdatedAt = "2026-10-01T03:00:00.123456789Z"
			current := preview
			current.UpdatedAt = "2026-10-01T03:00:00.123457Z"
			current.ExpiresAt = "2026-10-01T03:00:00.123457Z"
			ops.doc.Actions[preview.ActionID] = current
			if err := s.recordActionPrecheckFailure(preview, errors.New("current failure")); err != nil {
				t.Fatal(err)
			}
			got := ops.doc.Actions[preview.ActionID]
			if got.Status != "blocked" || got.LastError != "current failure" || got.AccountID != current.AccountID {
				t.Fatalf("matching failure not recorded: %+v", got)
			}
		})
	}
}

type mutateActionEvidenceReader struct {
	*riskActionReplayReader
	mutate func()
}

func (r mutateActionEvidenceReader) GetIPEvidence(context.Context, string, int) ([]evidence.Evidence, error) {
	r.mutate()
	return r.evidence, nil
}

func TestActionFailureMemoryDeliveryDoesNotSendChangedAccount(t *testing.T) {
	s, reader, a := riskActionReplay(t)
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"action_id":"owned-receipt","status":"completed"}`))
	}))
	defer remote.Close()
	s.actionMasterKey = []byte("isolated-replay-master-key-123456")
	secret, err := s.encryptConnectorSecret("isolated-secret")
	if err != nil {
		t.Fatal(err)
	}
	s.operations.doc.Connectors[a.ConnectorID] = ActionConnector{ConnectorID: a.ConnectorID, Enabled: true, Mode: "active", EndpointURL: remote.URL, EncryptedSecret: secret}
	a.IdempotencyKey = "owned-change"
	a.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.operations.doc.Actions[a.ActionID] = a
	s.reader = mutateActionEvidenceReader{riskActionReplayReader: reader, mutate: func() {
		s.operations.mu.Lock()
		current := s.operations.doc.Actions[a.ActionID]
		current.AccountID = "changed-account"
		s.operations.doc.Actions[a.ActionID] = current
		s.operations.mu.Unlock()
	}}
	s.deliverAction(a.ActionID, false)
	got := s.operations.doc.Actions[a.ActionID]
	if calls.Load() != 0 || got.Status != "pending" || got.AccountID != "changed-account" {
		t.Fatalf("changed intent sent/mutated: calls=%d status=%s account=%s", calls.Load(), got.Status, got.AccountID)
	}
}
