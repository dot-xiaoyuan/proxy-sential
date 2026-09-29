package controlplane

import (
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/srunapi"
	"testing"
	"time"
)

func TestReconfirmationPreservesSentActionsAndRetiresOnlyUnsent(t *testing.T) {
	for _, name := range []string{"unsent", "running", "retried", "reserved", "missing"} {
		t.Run(name, func(t *testing.T) {
			ops, _ := newOperationsState("", "")
			s := &Server{operations: ops}
			now := time.Now().UTC()
			ops.doc.Actions["done"] = EnforcementAction{ActionID: "done", Status: "succeeded"}
			a := EnforcementAction{ActionID: "old", Status: "blocked"}
			switch name {
			case "running":
				a.Status = "running"
			case "retried":
				a.RetryCount = 1
			case "reserved":
				a.PolicyParameters.NativeIntent = &srunapi.DispatchIntent{}
			}
			if name != "missing" {
				ops.doc.Actions["old"] = a
			}
			e := policy.Execution{Stages: []policy.StageState{{Key: "key", ActionIDs: []string{"done", "old"}}}}
			err := s.resetUnsentDisconnectsLocked(&e, 0, "fingerprint", now)
			if name == "unsent" {
				if err != nil || ops.doc.Actions["old"].Status != "cancelled" || len(e.Stages[0].ActionIDs) != 1 || e.Stages[0].Key == "key" {
					t.Fatal("unsent action not replaced")
				}
			} else {
				if err == nil || e.Stages[0].Key != "key" || len(e.Stages[0].ActionIDs) != 2 {
					t.Fatal("uncertain action silently replaced")
				}
			}
			if ops.doc.Actions["done"].Status != "succeeded" {
				t.Fatal("completion history lost")
			}
		})
	}
}
