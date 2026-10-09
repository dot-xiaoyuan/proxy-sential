package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SQL rounds timestamps to microseconds. Update time identifies an attempt or
// operator retry; creation time and historical error text do not. Retain all
// retry/receipt and subject/proof fields so an old failure cannot change a newer one.
func actionPrecheckFingerprint(a EnforcementAction) [32]byte {
	a.CreatedAt = ""
	a.LastError = ""
	for _, stamp := range []*string{&a.UpdatedAt, &a.ExpiresAt, &a.CooldownUntil, &a.NextAttemptAt} {
		if parsed, err := time.Parse(time.RFC3339Nano, *stamp); err == nil {
			*stamp = parsed.UTC().Round(time.Microsecond).Format(time.RFC3339Nano)
		}
	}
	return operationFingerprint("action", a)
}

func (s *Server) recordActionPrecheckFailure(preview EnforcementAction, cause error) error {
	if cause == nil || (preview.Status != "pending" && preview.Status != "running") {
		return nil
	}
	if s.operations.db != nil && !s.operations.readView {
		ctx, cancel := contextWithRequestTimeout(context.Background())
		defer cancel()
		view, tx, err := s.targetActionMutation(ctx, preview.ActionID)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		return view.recordActionPrecheckFailure(preview, cause)
	}
	s.operations.mu.Lock()
	current, exists := s.operations.doc.Actions[preview.ActionID]
	if !exists || current.Status != preview.Status || actionPrecheckFingerprint(current) != actionPrecheckFingerprint(preview) {
		s.operations.mu.Unlock()
		return nil
	}
	current.Status = "blocked"
	current.LastError = cause.Error()
	current.NextAttemptAt = ""
	current.PrecheckRetryable = temporaryActionPrecheckFailure(cause)
	if current.PrecheckRetryable {
		current.PrecheckRetryCount = min(current.PrecheckRetryCount+1, 5)
		if current.PrecheckRetryCount < 5 {
			current.Status = "pending"
			current.NextAttemptAt = time.Now().UTC().Add(15 * time.Second << uint(current.PrecheckRetryCount-1)).Format(time.RFC3339Nano)
		}
	}
	current.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.operations.doc.Actions[current.ActionID] = current
	err := s.operations.saveLocked()
	s.operations.mu.Unlock()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		name := "enforcement.precheck_blocked"
		if current.Status == "pending" {
			name = "enforcement.precheck_retry"
		}
		s.appendAudit(ctx, name, current.ActionID, fmt.Sprintf("%s; precheck=%d; %s", current.Status, current.PrecheckRetryCount, cause.Error()))
	}
	return err
}

func temporaryActionPrecheckFailure(cause error) bool {
	var unavailable actionPrecheckReadError
	return errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) || errors.Is(cause, errIdentityAuthorityUnavailable) || errors.As(cause, &unavailable)
}
