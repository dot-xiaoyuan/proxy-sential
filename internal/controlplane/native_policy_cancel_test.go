package controlplane

import (
	"os"
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestPolicyRevokeStopsRunningNativeChildrenAndPreservesCompleted(t *testing.T) {
	ops, err := newOperationsState("", "")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{operations: ops}
	now := time.Now().UTC()
	e := policy.Execution{ID: "round", State: "executing", Definition: policy.Definition{CooldownSeconds: 60}, Stages: []policy.StageState{{Status: "pending_action"}}}
	for _, status := range []string{"pending", "running", "succeeded"} {
		ops.doc.Actions[status] = EnforcementAction{ActionID: status, Status: status, ActionType: "session.disconnect", NextAttemptAt: formatDBTime(now), PolicyParameters: PolicyActionParameters{ExecutionID: e.ID, NativeSelected: true, Operation: "disconnect"}}
	}
	s.releasePolicyActionsLocked(e, now, "manual-revoke")
	e = policy.Revoke(e, now)
	for _, id := range []string{"pending", "running"} {
		a := ops.doc.Actions[id]
		if a.Status != "cancelled" || a.NextAttemptAt != "" {
			t.Fatalf("child %s not stopped: %+v", id, a)
		}
	}
	if ops.doc.Actions["succeeded"].Status != "succeeded" || len(ops.doc.Actions) != 3 {
		t.Fatal("completed disconnect rewritten or fictitious release created")
	}
	if e.State != "revoked" || e.Stages[0].Status != "cancelled" || !e.CooldownUntil.Equal(now.Add(time.Minute)) {
		t.Fatalf("round not cancelled: %+v", e)
	}
}

func TestNativePolicyCancellationPostgresSurvivesReload(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	ops, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	now := time.Now().UTC()
	id := "cancel-round-" + now.Format("150405.000000000")
	e := policy.Execution{ID: id, PolicyID: "sandbox", AccountID: "test", State: "executing", Definition: policy.Definition{CooldownSeconds: 60}, Stages: []policy.StageState{{Status: "pending_action", ActionIDs: []string{id + "-child"}}}}
	s := &Server{operations: ops}
	ops.mu.Lock()
	ops.doc.Actions[id+"-child"] = EnforcementAction{ActionID: id + "-child", IdempotencyKey: id, Status: "running", ActionType: "session.disconnect", CreatedAt: formatDBTime(now), UpdatedAt: formatDBTime(now), PolicyParameters: PolicyActionParameters{ExecutionID: id, NativeSelected: true, Operation: "disconnect"}}
	s.releasePolicyActionsLocked(e, now, "manual-revoke")
	ops.doc.PolicyExecutions[id] = policy.Revoke(e, now)
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.db.Close()
	restored := reloaded.doc.PolicyExecutions[id]
	if restored.State != "revoked" || !restored.CooldownUntil.Equal(now.Add(time.Minute)) {
		t.Fatalf("round lost: %+v", restored)
	}
	child := reloaded.doc.Actions[id+"-child"]
	if child.Status != "cancelled" || !child.PolicyParameters.NativeSelected || child.NextAttemptAt != "" {
		t.Fatalf("child lost: %+v", child)
	}
	// No active controller is necessary: a cancelled native marker must also block
	// accidental generic fallback when runtime configuration is absent after restart.
	restarted := &Server{operations: reloaded}
	restarted.deliverAction(child.ActionID, false)
	if reloaded.doc.Actions[child.ActionID].Status != "cancelled" {
		t.Fatal("cancelled child resumed")
	}
}
