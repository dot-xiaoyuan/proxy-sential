package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/srunapi"
	"time"
)

// NativeActionRuntime is provisioned by trusted startup or versioned managed
// configuration, never by an event or HTTP action body. Managed shadow execution
// additionally requires a persisted, immutable designated-account review grant.
type NativeActionRuntime struct {
	CredentialsFrom4K bool
	TestAccount       string
	Probe             func(context.Context) (int64, error)
	Client            srunapi.NativeDisconnect
	Read              func(context.Context) (legacy4k.OnlineInventory, error)
	CampusID          string
	AccessDomain      string
	DropType          string
	Now               func() time.Time
}

func (s *Server) nativeAuthorization(ctx context.Context, a EnforcementAction) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	current, connector, stopped, exists, err := s.readNativeActionAdmission(ctx, a.ActionID)
	if err != nil {
		return err
	}
	reviewManual := a.PolicyParameters.SharedReview != nil && connector.Mode == "shadow"
	if s.readOnly || !exists || stopped || current.Status != "running" || current.Mode != "active" || !connector.Enabled || (!reviewManual && connector.Mode != "active") || (!reviewManual && connector.ConnectorType != "srun4k" && !connector.ShadowReady && !s.nativeTestAccountAllowed(a.ConnectorID, a.AccountID, a.CampusID, a.PolicyParameters.AccessDomain)) {
		return fmt.Errorf("native action admission unavailable")
	}
	if current.ActionType != a.ActionType || current.IP != a.IP || current.CampusID != a.CampusID || current.PolicyParameters.AccessDomain != a.PolicyParameters.AccessDomain || current.AccountID != a.AccountID || current.SessionID != a.SessionID || current.IdempotencyKey != a.IdempotencyKey || current.ConnectorID != a.ConnectorID {
		return fmt.Errorf("native action identity changed")
	}
	// Authorize the exact admitted attempt. A new running generation with the
	// same account/session cannot lend its evidence or lease to an old sender.
	if actionReceiptFingerprint(current) != actionReceiptFingerprint(a) {
		return errActionReceiptConflict
	}
	if until, err := time.Parse(time.RFC3339Nano, connector.CircuitOpenUntil); err == nil && until.After(time.Now()) {
		return fmt.Errorf("native connector circuit is open")
	}
	if reviewManual && (current.PolicyParameters.SharedReview == nil || *current.PolicyParameters.SharedReview != *a.PolicyParameters.SharedReview) {
		return fmt.Errorf("manual grant identity changed")
	}
	if reviewManual {
		err = s.validateSharedDisconnectDelivery(ctx, current)
	} else {
		err = s.validatePolicyDeliveryContext(ctx, current)
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

// deliverNativeAction participates in the existing pending/running scheduler.
// A stored native intent never falls through to generic HTTP after restart or
// removal of configuration. Repeated pending evaluations only reconcile.
func (s *Server) deliverNativeAction(id string, revoke bool) bool {
	s.operations.mu.Lock()
	a, ok := s.operations.doc.Actions[id]
	runtime, configured := s.nativeRuntime(a.ConnectorID)
	if ok && a.Status == "pending" && !actionDispatchDue(a, time.Now().UTC()) {
		native := configured || a.PolicyParameters.NativeSelected || a.PolicyParameters.NativeIntent != nil || a.PolicyParameters.SharedReview != nil || s.operations.doc.Connectors[a.ConnectorID].ConnectorType == "srun4k"
		s.operations.mu.Unlock()
		return native
	}
	if ok && !configured && s.operations.doc.Connectors[a.ConnectorID].ConnectorType == "srun4k" {
		s.operations.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.refreshSRunConnector(ctx, a.ConnectorID)
		cancel()
		if _, refreshed := s.nativeRuntime(a.ConnectorID); refreshed {
			return s.deliverNativeAction(id, revoke)
		}
		s.recordActionPrecheckFailure(a, errors.New("managed 4K runtime unavailable"))
		return true
	}
	if ok && a.PolicyParameters.SharedReview != nil && !configured {
		s.operations.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		managed, _, err := s.managedDisconnectRuntime(ctx, a.ConnectorID)
		if err != nil {
			s.recordActionPrecheckFailure(a, errors.New("managed native runtime unavailable"))
			return true
		}
		s.setNativeRuntime(a.ConnectorID, managed)
		return s.deliverNativeAction(id, revoke)
	}
	marked := a.PolicyParameters.NativeIntent != nil || s.operations.doc.Connectors[a.ConnectorID].ConnectorType == "srun4k"
	if !ok || (!configured && !marked && !a.PolicyParameters.NativeSelected) {
		s.operations.mu.Unlock()
		return false
	}
	if a.Status != "pending" || s.operations.lockErr != nil {
		s.operations.mu.Unlock()
		return true
	}
	connector := s.operations.doc.Connectors[a.ConnectorID]
	if connector.ConnectorType == "srun4k" && (a.ActionType == "account.notify" || a.ActionType == "account.disable_account") {
		if revoke || !configured || s.operations.db == nil {
			s.operations.mu.Unlock()
			s.recordActionPrecheckFailure(a, errors.New("native runtime or action capability unavailable"))
			return true
		}
		a.Status = "running"
		a.PrecheckRetryable = false
		a.NextAttemptAt = ""
		a.LastError = ""
		a.PolicyParameters.NativeSelected = true
		a.UpdatedAt = formatDBTime(time.Now().UTC())
		s.operations.doc.Actions[id] = a
		err := s.operations.saveLocked()
		a = s.operations.doc.Actions[id]
		s.operations.mu.Unlock()
		if err != nil {
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err = s.nativeAuthorization(ctx, a); err != nil {
			s.recordActionPrecheckFailure(a, err)
			return true
		}
		if a.ActionType == "account.notify" {
			parameters, _ := json.Marshal(map[string]any{"action_id": a.ActionID, "policy_execution_id": a.PolicyParameters.ExecutionID})
			_, err = s.operations.db.ExecContext(ctx, `INSERT INTO notification_outbox(notification_id,idempotency_key,account_id,template,parameters) VALUES($1,$2,$3,$4,$5) ON CONFLICT(idempotency_key) DO NOTHING`, "notification-"+a.IdempotencyKey, a.IdempotencyKey, a.AccountID, a.PolicyParameters.Template, parameters)
			if err != nil {
				s.finishDeliveredAction(a, "failed", "", "notification queue unavailable")
				return true
			}
			s.finishDeliveredAction(a, "succeeded", "notification-"+a.IdempotencyKey, "")
			s.appendAudit(ctx, "enforcement.notification_queued", id, "succeeded")
			return true
		}
		controller, supported := runtime.Client.(interface {
			RequestSafeDisableChecked(context.Context, string, int, func(context.Context) error) error
		})
		if !supported || a.DurationSeconds <= 0 {
			s.recordActionPrecheckFailure(a, errors.New("4K safe-disable capability unavailable"))
			return true
		}
		err = controller.RequestSafeDisableChecked(ctx, a.AccountID, a.DurationSeconds, func(guard context.Context) error { return s.nativeAuthorization(guard, a) })
		if err != nil {
			if errors.Is(err, srunapi.ErrDispatchPrevented) {
				s.recordActionPrecheckFailure(a, err)
			} else {
				s.finishDeliveredAction(a, "failed", "", "4K SafeDisable request failed")
			}
			return true
		}
		s.finishDeliveredAction(a, "succeeded", "safe-disable:"+a.IdempotencyKey, "")
		s.appendAudit(ctx, "enforcement.srun4k_safe_disable", id, "accepted")
		return true
	}
	if !configured || s.operations.db == nil || runtime.Client == nil || runtime.Read == nil || revoke || (a.ActionType != "disconnect" && a.ActionType != "session.disconnect") {
		s.operations.mu.Unlock()
		s.recordActionPrecheckFailure(a, errors.New("native runtime or action capability unavailable"))
		return true
	}
	if (runtime.CampusID != "" && a.CampusID != runtime.CampusID) || (runtime.AccessDomain != "" && a.PolicyParameters.AccessDomain != runtime.AccessDomain) {
		s.operations.mu.Unlock()
		s.recordActionPrecheckFailure(a, errors.New("native source scope mismatch"))
		return true
	}
	now := runtime.Now
	if now == nil {
		now = time.Now
	}
	a.Status = "running"
	a.PrecheckRetryable = false
	a.NextAttemptAt = ""
	a.LastError = ""
	a.PolicyParameters.NativeSelected = true
	a.UpdatedAt = formatDBTime(time.Now().UTC())
	s.operations.doc.Actions[id] = a
	err := s.operations.saveLocked()
	a = s.operations.doc.Actions[id]
	db := s.operations.db
	s.operations.mu.Unlock()
	if err != nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err = s.nativeAuthorization(ctx, a); err != nil {
		s.recordActionPrecheckFailure(a, err)
		return true
	}
	if a.PolicyParameters.NativeIntent == nil {
		if (runtime.CampusID != "" && a.CampusID != runtime.CampusID) || (runtime.AccessDomain != "" && a.PolicyParameters.AccessDomain != runtime.AccessDomain) {
			s.recordActionPrecheckFailure(a, errors.New("native source scope mismatch"))
			return true
		}
		inventory, readErr := runtime.Read(ctx)
		if readErr != nil {
			s.recordActionPrecheckFailure(a, errors.New("native identity unavailable"))
			return true
		}
		target, bindErr := srunapi.BindDisconnect(inventory, a.AccountID, a.SessionID, now().UTC(), 30*time.Second)
		records, _, recordsErr := inventory.IdentityRecordsWithStatsContext(ctx)
		matchesIP := false
		for _, record := range records {
			if record["session_id"] == a.SessionID && record["account_id"] == a.AccountID && record["ip"] == a.IP {
				matchesIP = true
			}
		}
		if bindErr != nil || recordsErr != nil || !matchesIP {
			s.recordActionPrecheckFailure(a, errors.New("native confirmed session no longer matches"))
			return true
		}
		intent := srunapi.DispatchIntent{Key: a.IdempotencyKey, ConnectorID: a.ConnectorID, Target: target, DropType: runtime.DropType}
		s.operations.mu.Lock()
		current := s.operations.doc.Actions[id]
		if s.operations.lockErr != nil {
			err = s.operations.lockErr
			s.operations.mu.Unlock()
			s.auditDeliveryResultError(a, "native_binding", err)
			return true
		}
		if current.Status != "running" || actionReceiptFingerprint(current) != actionReceiptFingerprint(a) {
			s.operations.mu.Unlock()
			s.auditDeliveryResultError(a, "native_binding", errActionReceiptConflict)
			return true
		}
		current.PolicyParameters.NativeIntent = &intent
		s.operations.doc.Actions[id] = current
		err = s.operations.saveLocked()
		current = s.operations.doc.Actions[id]
		s.operations.mu.Unlock()
		if err != nil {
			return true
		}
		a = current
	}
	intent := *a.PolicyParameters.NativeIntent
	if intent.Key != a.IdempotencyKey || intent.ConnectorID != a.ConnectorID || intent.Target.Account != a.AccountID || intent.Target.SessionID != a.SessionID || intent.DropType != runtime.DropType {
		s.recordActionPrecheckFailure(a, errors.New("native intent scope mismatch"))
		return true
	}
	executor := srunapi.Executor{Journal: srunapi.Journal{DB: db}, Native: runtime.Client, Read: runtime.Read, Now: now, MaxAge: 30 * time.Second, Authorize: func(c context.Context, _ srunapi.DispatchIntent) error { return s.nativeAuthorization(c, a) }}
	result, stepErr := executor.Step(ctx, intent)
	// Observations are persisted by Executor. Keep uncertain outcomes in the
	// existing queue with a bounded polling interval, without incrementing sends.
	s.operations.mu.Lock()
	current := s.operations.doc.Actions[id]
	if s.operations.lockErr != nil {
		err = s.operations.lockErr
	} else if current.Status != "running" || actionReceiptFingerprint(current) != actionReceiptFingerprint(a) {
		err = errActionReceiptConflict
	} else {
		current.Status = "pending"
		current.NextAttemptAt = formatDBTime(time.Now().UTC().Add(10 * time.Second))
		current.UpdatedAt = formatDBTime(time.Now().UTC())
		current.LastError = "awaiting native reconciliation"
		if stepErr != nil {
			current.LastError = "native processing requires reconciliation or review"
		}
		if result.Delivery == "rejected" {
			current.Status = "failed"
			current.NextAttemptAt = ""
			current.LastError = "native API explicitly rejected the request"
		}
		if stepErr == nil && result.Observation == "absent" && result.Delivery != "rejected" {
			current.Status = "succeeded"
			current.NextAttemptAt = ""
			current.ExpiresAt = ""
			current.LastError = ""
			current.RemoteActionID = intent.Target.RawOnlineID
		}
		s.operations.doc.Actions[id] = current
		err = s.operations.saveLocked()
	}
	s.operations.mu.Unlock()
	if err == nil {
		auditCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		s.appendAudit(auditCtx, "enforcement.native_observed", id, result.Delivery+":"+result.Observation)
		stop()
	} else {
		s.auditDeliveryResultError(a, "native_observed", err)
	}
	return true
}
