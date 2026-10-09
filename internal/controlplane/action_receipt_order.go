package controlplane

import (
	"context"
	"errors"
	"time"
)

var errActionReceiptConflict = errors.New("动作状态已更新，回执与当前结果冲突")

// Receipt writes belong to one admitted attempt. Retain update time so an old
// response cannot finish a running lease recovered after restart. PostgreSQL
// rounds timestamps, so compare them at the same precision as stored values.
func actionReceiptFingerprint(a EnforcementAction) [32]byte {
	for _, stamp := range []*string{&a.CreatedAt, &a.UpdatedAt, &a.ExpiresAt, &a.CooldownUntil, &a.NextAttemptAt} {
		if parsed, err := time.Parse(time.RFC3339Nano, *stamp); err == nil {
			*stamp = parsed.UTC().Round(time.Microsecond).Format(time.RFC3339Nano)
		}
	}
	return operationFingerprint("action", a)
}

func (s *Server) finishActionReceipt(preview EnforcementAction, status, remoteID, lastError string) error {
	if s.operations.db != nil && !s.operations.readView {
		ctx, cancel := contextWithRequestTimeout(context.Background())
		defer cancel()
		view, tx, err := s.targetActionMutation(ctx, preview.ActionID)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		return view.finishActionReceipt(preview, status, remoteID, lastError)
	}
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	current, exists := s.operations.doc.Actions[preview.ActionID]
	if !exists || actionReceiptFingerprint(current) != actionReceiptFingerprint(preview) {
		return errActionReceiptConflict
	}
	// Repeated terminal callbacks are acknowledged without changing versions,
	// parent recovery state, or connector circuit counters.
	if current.Status == status && (remoteID == "" || current.RemoteActionID == remoteID) && current.LastError == lastError {
		return nil
	}
	// A signed completion may resolve an exhausted transport failure. A failure
	// cannot regress a confirmed completion, recovery, cancellation, or shadow.
	if current.Status != "pending" && current.Status != "running" && !(current.Status == "failed" && (status == "succeeded" || status == "revoked")) {
		return errActionReceiptConflict
	}
	return s.finishActionLocked(preview.ActionID, status, remoteID, lastError)
}

func (s *Server) finishDeliveredAction(a EnforcementAction, status, remoteID, lastError string) {
	s.auditDeliveryResultError(a, status, s.finishActionReceipt(a, status, remoteID, lastError))
}

func (s *Server) auditDeliveryResultError(a EnforcementAction, status string, err error) {
	if err != nil {
		outcome := "receipt_storage_failed:" + status
		if errors.Is(err, errActionReceiptConflict) {
			outcome = "receipt_conflict:" + status
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.appendAudit(ctx, "enforcement.delivery_receipt", a.ActionID, outcome)
	}
}

func (s *Server) scheduleActionRetryForAttempt(preview EnforcementAction, lastError string) error {
	if s.operations.db != nil && !s.operations.readView {
		ctx, cancel := contextWithRequestTimeout(context.Background())
		defer cancel()
		view, tx, err := s.targetActionMutation(ctx, preview.ActionID)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		return view.scheduleActionRetryForAttempt(preview, lastError)
	}
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	current, exists := s.operations.doc.Actions[preview.ActionID]
	if !exists || actionReceiptFingerprint(current) != actionReceiptFingerprint(preview) {
		return errActionReceiptConflict
	}
	return s.scheduleActionRetryLocked(preview.ActionID, lastError)
}
