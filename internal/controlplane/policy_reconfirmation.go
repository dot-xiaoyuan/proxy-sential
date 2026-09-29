package controlplane

import (
	"fmt"
	"proxy-sentinel/internal/policy"
	"time"
)

// A new confirmation may replace only provably unsent actions. Completed
// actions remain in the stage; uncertain sends require reconciliation first.
func (s *Server) resetUnsentDisconnectsLocked(e *policy.Execution, index int, fingerprint string, now time.Time) error {
	st := &e.Stages[index]
	if len(st.ActionIDs) == 0 {
		return nil
	}
	keep := []string{}
	retire := []string{}
	for _, id := range st.ActionIDs {
		a, ok := s.operations.doc.Actions[id]
		if !ok {
			return fmt.Errorf("prior action record unavailable")
		}
		if a.Status == "succeeded" {
			keep = append(keep, id)
			continue
		}
		if a.PolicyParameters.NativeIntent != nil || a.RetryCount > 0 || (a.Status != "pending" && a.Status != "blocked") {
			return fmt.Errorf("prior action may have been sent; reconcile before confirming again")
		}
		retire = append(retire, id)
	}
	for _, id := range retire {
		a := s.operations.doc.Actions[id]
		a.Status = "cancelled"
		a.NextAttemptAt = ""
		a.ExpiresAt = ""
		a.UpdatedAt = formatDBTime(now)
		a.LastError = "已被新的人工确认替代，未重新发送旧动作"
		s.operations.doc.Actions[id] = a
	}
	st.ActionIDs = keep
	st.Key = policy.StableID(st.Key, "manual-reconfirmation", fingerprint)
	st.CompletedAt = time.Time{}
	st.CompletedPausedSeconds = 0
	return nil
}
