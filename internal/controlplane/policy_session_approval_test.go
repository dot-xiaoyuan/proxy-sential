package controlplane

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestManualDisconnectFanoutRequiresConfirmedSessions(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.operations.doc.Connectors["c"] = ActionConnector{ConnectorID: "c", Enabled: true, Mode: "active", ShadowReady: true, ActionMapping: map[string]string{"account_policy_v1": "supported", "session.disconnect": "drop"}}
	now := time.Now().UTC()
	ss := []policy.Session{{ID: "one", AccountID: "a", Source: "auth", CampusID: "c", AccessDomain: "nas", IP: "192.0.2.1", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}}
	e := policy.Execution{ID: "round", AccountID: "a", Definition: policy.Definition{Mode: "manual", Stages: []policy.Stage{{ConnectorID: "c", Action: "disconnect"}}}, Stages: []policy.StageState{{Key: "stage"}}}
	s.createPolicyActionsLocked(&e, 0, ss, now)
	if len(s.operations.doc.Actions) != 0 || e.Stages[0].Status != "awaiting_approval" {
		t.Fatal("missing confirmation created actions")
	}
	approved, err := policy.SessionApprovalBindings("a", ss, now)
	if err != nil {
		t.Fatal(err)
	}
	e.Stages[0].ApprovedSessionBindings = approved
	s.createPolicyActionsLocked(&e, 0, ss, now)
	if len(s.operations.doc.Actions) != 1 {
		t.Fatal("confirmed target not created")
	}
	second := ss[0]
	second.ID = "two"
	second.IP = "192.0.2.2"
	ss = append(ss, second)
	s.createPolicyActionsLocked(&e, 0, ss, now.Add(time.Second))
	if len(s.operations.doc.Actions) != 1 || e.Stages[0].Status != "awaiting_approval" {
		t.Fatal("new login inherited old confirmation")
	}
}

func TestReconfirmedDisconnectCreatesFreshUnsentTargetsOnly(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "completed"}[completed], func(t *testing.T) {
			s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
			s.operations.doc.Connectors["c"] = ActionConnector{ConnectorID: "c", Enabled: true, Mode: "active", ShadowReady: true, ActionMapping: map[string]string{"account_policy_v1": "supported", "session.disconnect": "drop"}}
			now := time.Now().UTC()
			ss := []policy.Session{{ID: "one", AccountID: "a", Source: "auth", CampusID: "c", AccessDomain: "nas", IP: "192.0.2.1", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}}
			bindings, _ := policy.SessionApprovalBindings("a", ss, now)
			e := policy.Execution{ID: "round", AccountID: "a", Definition: policy.Definition{Mode: "manual", Stages: []policy.Stage{{ConnectorID: "c", Action: "disconnect"}}}, Stages: []policy.StageState{{Key: "stage", ApprovedSessionBindings: bindings}}}
			s.createPolicyActionsLocked(&e, 0, ss, now)
			oldID := e.Stages[0].ActionIDs[0]
			if completed {
				a := s.operations.doc.Actions[oldID]
				a.Status = "succeeded"
				s.operations.doc.Actions[oldID] = a
			}
			second := ss[0]
			second.ID = "two"
			second.IP = "192.0.2.2"
			ss = append(ss, second)
			if err := s.resetUnsentDisconnectsLocked(&e, 0, "new-confirmation", now); err != nil {
				t.Fatal(err)
			}
			e.Stages[0].ApprovedSessionBindings, _ = policy.SessionApprovalBindings("a", ss, now)
			s.createPolicyActionsLocked(&e, 0, ss, now)
			wantStatus := "cancelled"
			wantTotal := 3
			if completed {
				wantStatus = "succeeded"
				wantTotal = 2
			}
			if s.operations.doc.Actions[oldID].Status != wantStatus || len(s.operations.doc.Actions) != wantTotal || len(e.Stages[0].ActionIDs) != 2 {
				t.Fatal("wrong replacement or repeated completed session", s.operations.doc.Actions)
			}
			s.createPolicyActionsLocked(&e, 0, ss, now.Add(time.Second))
			if len(s.operations.doc.Actions) != wantTotal {
				t.Fatal("reconfirmation retry duplicated targets")
			}
		})
	}
}
