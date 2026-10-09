package controlplane

import (
	"reflect"
	"time"
)

const actionTransportRetryLimit = 3

// The operator retries the same recovery intent. No new lease or external
// idempotency key is manufactured, and transport retry accounting is preserved.
func (s *Server) existingReleaseActionLocked(parent EnforcementAction) (EnforcementAction, bool, bool) {
	for _, child := range s.operations.doc.Actions {
		if child.ParentActionID != parent.ActionID || child.ActionType != "release" {
			continue
		}
		// An explicit operator request may retry an exhausted recovery without
		// resetting its cumulative failures. The next failed transport therefore
		// stops again rather than receiving another automatic retry budget.
		retryable := child.Status == "blocked" || (child.Status == "failed" && child.RetryCount >= actionTransportRetryLimit)
		if parent.Status != "succeeded" || parent.Mode != "active" || child.Mode != "active" || !retryable || child.RemoteActionID != "" || s.operations.doc.Connectors[parent.ConnectorID].ConnectorType == "srun4k" {
			return child, true, false
		}
		if child.IdempotencyKey != parent.IdempotencyKey+":release" || child.ConnectorID != parent.ConnectorID || child.AccountID != parent.AccountID || child.IP != parent.IP || child.SessionID != parent.SessionID || child.EndpointID != parent.EndpointID || child.CampusID != parent.CampusID || child.SubjectType != parent.SubjectType || child.SubjectID != parent.SubjectID || child.CaseID != parent.CaseID || child.RulesetVersion != parent.RulesetVersion || !reflect.DeepEqual(child.EvidenceIDs, parent.EvidenceIDs) || !reflect.DeepEqual(child.PolicyParameters, parent.PolicyParameters) {
			return child, true, false
		}
		child.Status = "pending"
		child.PrecheckRetryCount = 0
		child.PrecheckRetryable = false
		child.NextAttemptAt = ""
		child.LastError = ""
		blockers := make([]string, 0, len(child.Blockers))
		for _, blocker := range child.Blockers {
			if blocker != "connector_or_global_stop_changed" {
				blockers = append(blockers, blocker)
			}
		}
		child.Blockers = blockers
		child.UpdatedAt = formatDBTime(time.Now().UTC())
		s.operations.doc.Actions[child.ActionID] = child
		return child, true, true
	}
	return EnforcementAction{}, false, false
}

func actionDispatchDue(a EnforcementAction, now time.Time) bool {
	if a.Status != "pending" {
		return false
	}
	if due, err := time.Parse(time.RFC3339Nano, a.NextAttemptAt); err == nil && due.After(now) {
		// Existing native intents reconcile through their irreversible journal
		// gate. Preserve restart reconciliation; a failed precheck still waits.
		if a.PolicyParameters.NativeIntent != nil && !a.PrecheckRetryable {
			return true
		}
		return false
	}
	return true
}
