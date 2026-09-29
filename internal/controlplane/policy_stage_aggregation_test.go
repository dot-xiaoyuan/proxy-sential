package controlplane

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestPolicyStageAggregationDoesNotOverstateAccountCompletion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []string
		want     string
	}{
		{"all_success", []string{"succeeded", "succeeded"}, "succeeded"},
		{"success_waiting", []string{"succeeded", "pending"}, "partial_success"},
		{"success_running", []string{"succeeded", "running"}, "partial_success"},
		{"success_failed", []string{"succeeded", "failed"}, "partial_success"},
		{"success_missing", []string{"succeeded", "missing"}, "partial_success"},
		{"all_waiting", []string{"pending", "running"}, "pending_action"},
		{"all_failed", []string{"blocked", "failed"}, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops, err := newOperationsState("", "")
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{operations: ops}
			now := time.Now().UTC()
			st := policy.StageState{Status: "succeeded", CompletedAt: now.Add(-time.Minute), CompletedPausedSeconds: 5}
			for i, status := range tc.statuses {
				id := string(rune('a' + i))
				st.ActionIDs = append(st.ActionIDs, id)
				if status != "missing" {
					ops.doc.Actions[id] = EnforcementAction{Status: status}
				}
			}
			e := policy.Execution{Stages: []policy.StageState{st}}
			s.refreshPolicyStagesLocked(&e, now)
			got := e.Stages[0]
			if got.Status != tc.want {
				t.Fatalf("got %s want %s", got.Status, tc.want)
			}
			if tc.want != "succeeded" && (!got.CompletedAt.IsZero() || got.CompletedPausedSeconds != 0) {
				t.Fatal("incomplete account retained stale completion boundary")
			}
		})
	}
}

func TestPolicyStageRefreshPreservesRevokedRound(t *testing.T) {
	ops, err := newOperationsState("", "")
	if err != nil {
		t.Fatal(err)
	}
	ops.doc.Actions["child"] = EnforcementAction{Status: "cancelled"}
	s := &Server{operations: ops}
	e := policy.Execution{State: "revoked", Stages: []policy.StageState{{Status: "cancelled", ActionIDs: []string{"child"}}}}
	s.refreshPolicyStagesLocked(&e, time.Now())
	if e.Stages[0].Status != "cancelled" {
		t.Fatal("refresh overwrote revoked stage")
	}
}

func TestPolicyStageCompletesOnlyAfterLastSession(t *testing.T) {
	ops, err := newOperationsState("", "")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{operations: ops}
	now := time.Now().UTC()
	ops.doc.Actions["a"] = EnforcementAction{Status: "succeeded"}
	ops.doc.Actions["b"] = EnforcementAction{Status: "pending"}
	e := policy.Execution{PausedSeconds: 9, Stages: []policy.StageState{{Status: "pending_action", ActionIDs: []string{"a", "b"}}}}
	s.refreshPolicyStagesLocked(&e, now)
	if e.Stages[0].Status != "partial_success" || !e.Stages[0].CompletedAt.IsZero() {
		t.Fatal("completed before final session")
	}
	ops.doc.Actions["b"] = EnforcementAction{Status: "succeeded"}
	completed := now.Add(2 * time.Minute)
	s.refreshPolicyStagesLocked(&e, completed)
	if e.Stages[0].Status != "succeeded" || !e.Stages[0].CompletedAt.Equal(completed) || e.Stages[0].CompletedPausedSeconds != 9 {
		t.Fatal("incorrect all-session completion boundary")
	}
	s.refreshPolicyStagesLocked(&e, completed.Add(time.Minute))
	if !e.Stages[0].CompletedAt.Equal(completed) {
		t.Fatal("repeated refresh changed completion boundary")
	}
}

func TestNewSessionRateLimitPrecedesNextStage(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.operations.doc.Connectors["c"] = ActionConnector{ConnectorID: "c", Enabled: true, Mode: "active", ShadowReady: true, ActionMapping: map[string]string{"account_policy_v1": "supported", "session.rate_limit": "limit"}}
	now := time.Now().UTC()
	p := policy.Definition{ID: "p", Mode: "automatic", WindowSeconds: 3600, Stages: []policy.Stage{{ConnectorID: "c", Action: "rate_limit", DurationSeconds: 600, RateKbps: 1000}, {ConnectorID: "c", Action: "disconnect"}}}
	e := policy.Execution{ID: "round", AccountID: "a", StartedAt: now.Add(-time.Minute), Definition: p, Stages: []policy.StageState{{Key: "lease"}}}
	ss := []policy.Session{{ID: "1", AccountID: "a", IP: "192.0.2.1", CampusID: "c", AccessDomain: "nas", Source: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}}
	s.createPolicyActionsLocked(&e, 0, ss, now)
	first := e.Stages[0].ActionIDs[0]
	a := s.operations.doc.Actions[first]
	a.Status = "succeeded"
	s.operations.doc.Actions[first] = a
	s.refreshPolicyStagesLocked(&e, now)
	second := ss[0]
	second.ID = "2"
	second.IP = "192.0.2.2"
	ss = append(ss, second)
	s.preparePolicyStagesLocked(&e, ss, now.Add(time.Second))
	if len(e.Stages[0].ActionIDs) != 2 || !e.Stages[0].CompletedAt.IsZero() {
		t.Fatal("new session did not invalidate completion")
	}
	d := policy.Advance(p, e, policy.Input{AccountID: "a", Known: true, Violated: true}, now.Add(time.Second))
	if d.Intent != nil || len(d.Execution.Stages) != 1 {
		t.Fatal("advanced before new session limit completed")
	}
	count := len(s.operations.doc.Actions)
	s.preparePolicyStagesLocked(&e, ss, now.Add(2*time.Second))
	if len(s.operations.doc.Actions) != count {
		t.Fatal("repeated evaluation duplicated session action")
	}
	added := s.operations.doc.Actions[e.Stages[0].ActionIDs[1]]
	if added.DurationSeconds >= 600 || added.PolicyParameters.LeaseID != "lease" {
		t.Fatal("new login reset lease duration or identity")
	}
	added.Status = "succeeded"
	s.operations.doc.Actions[added.ActionID] = added
	readyAt := now.Add(3 * time.Second)
	s.preparePolicyStagesLocked(&e, ss, readyAt)
	ready := policy.Advance(p, e, policy.Input{AccountID: "a", Known: true, Violated: true}, readyAt)
	if ready.Intent == nil || ready.Intent.StageIndex != 1 {
		t.Fatal("all sessions succeeded but next stage remained blocked")
	}
}
