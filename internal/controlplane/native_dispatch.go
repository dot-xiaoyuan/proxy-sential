package controlplane

import (
	"context"
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
	if err := ctx.Err(); err != nil {
		return err
	}
	s.operations.mu.Lock()
	current, exists := s.operations.doc.Actions[a.ActionID]
	connector := s.operations.doc.Connectors[a.ConnectorID]
	stopped := s.operations.doc.GlobalStop || s.operations.lockErr != nil
	s.operations.mu.Unlock()
	reviewManual := a.PolicyParameters.SharedReview != nil && connector.Mode == "shadow"
	if s.readOnly || !exists || stopped || current.Status != "running" || current.Mode != "active" || !connector.Enabled || (!reviewManual && connector.Mode != "active") || (!reviewManual && !connector.ShadowReady && !s.nativeTestAccountAllowed(a.ConnectorID, a.AccountID, a.CampusID, a.PolicyParameters.AccessDomain)) {
		return fmt.Errorf("native action admission unavailable")
	}
	if current.ActionType != a.ActionType || current.IP != a.IP || current.CampusID != a.CampusID || current.PolicyParameters.AccessDomain != a.PolicyParameters.AccessDomain || current.AccountID != a.AccountID || current.SessionID != a.SessionID || current.IdempotencyKey != a.IdempotencyKey || current.ConnectorID != a.ConnectorID {
		return fmt.Errorf("native action identity changed")
	}
	if until, err := time.Parse(time.RFC3339Nano, connector.CircuitOpenUntil); err == nil && until.After(time.Now()) {
		return fmt.Errorf("native connector circuit is open")
	}
	if reviewManual && (current.PolicyParameters.SharedReview == nil || *current.PolicyParameters.SharedReview != *a.PolicyParameters.SharedReview) {
		return fmt.Errorf("manual grant identity changed")
	}
	if reviewManual {
		return s.validateSharedDisconnectDelivery(ctx, current)
	}
	return s.validatePolicyDelivery(current)
}

// deliverNativeAction participates in the existing pending/running scheduler.
// A stored native intent never falls through to generic HTTP after restart or
// removal of configuration. Repeated pending evaluations only reconcile.
func (s *Server) deliverNativeAction(id string, revoke bool) bool {
	s.operations.mu.Lock()
	a, ok := s.operations.doc.Actions[id]
	runtime, configured := s.nativeActions[a.ConnectorID]
	if ok && a.PolicyParameters.SharedReview != nil && !configured {
		s.operations.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		managed, _, err := s.managedDisconnectRuntime(ctx, a.ConnectorID)
		if err != nil {
			s.finishAction(id, "blocked", "", "managed native runtime unavailable")
			return true
		}
		view := *s
		view.nativeActions = map[string]NativeActionRuntime{}
		for key, value := range s.nativeActions {
			view.nativeActions[key] = value
		}
		view.nativeActions[a.ConnectorID] = managed
		return view.deliverNativeAction(id, revoke)
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
	if !configured || s.operations.db == nil || runtime.Client == nil || runtime.Read == nil || runtime.CampusID == "" || runtime.AccessDomain == "" || revoke || (a.ActionType != "disconnect" && a.ActionType != "session.disconnect") {
		s.operations.mu.Unlock()
		s.finishAction(id, "blocked", "", "native runtime or action capability unavailable")
		return true
	}
	if a.CampusID != runtime.CampusID || a.PolicyParameters.AccessDomain != runtime.AccessDomain {
		s.operations.mu.Unlock()
		s.finishAction(id, "blocked", "", "native source scope mismatch")
		return true
	}
	now := runtime.Now
	if now == nil {
		now = time.Now
	}
	a.Status = "running"
	a.PolicyParameters.NativeSelected = true
	a.UpdatedAt = formatDBTime(time.Now().UTC())
	s.operations.doc.Actions[id] = a
	err := s.operations.saveLocked()
	db := s.operations.db
	s.operations.mu.Unlock()
	if err != nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if !marked {
		if err = s.nativeAuthorization(ctx, a); err != nil {
			s.finishAction(id, "blocked", "", err.Error())
			return true
		}
		if a.CampusID != runtime.CampusID || a.PolicyParameters.AccessDomain != runtime.AccessDomain {
			s.finishAction(id, "blocked", "", "native source scope mismatch")
			return true
		}
		inventory, readErr := runtime.Read(ctx)
		if readErr != nil {
			s.finishAction(id, "blocked", "", "native identity unavailable")
			return true
		}
		target, bindErr := srunapi.BindDisconnect(inventory, a.AccountID, a.SessionID, now().UTC(), 30*time.Second)
		records, recordsErr := inventory.IdentityRecords()
		matchesIP := false
		for _, record := range records {
			if record["session_id"] == a.SessionID && record["account_id"] == a.AccountID && record["ip"] == a.IP {
				matchesIP = true
			}
		}
		if bindErr != nil || recordsErr != nil || !matchesIP {
			s.finishAction(id, "blocked", "", "native confirmed session no longer matches")
			return true
		}
		intent := srunapi.DispatchIntent{Key: a.IdempotencyKey, ConnectorID: a.ConnectorID, Target: target, DropType: runtime.DropType}
		s.operations.mu.Lock()
		current := s.operations.doc.Actions[id]
		if current.Status != "running" {
			s.operations.mu.Unlock()
			return true
		}
		current.PolicyParameters.NativeIntent = &intent
		s.operations.doc.Actions[id] = current
		err = s.operations.saveLocked()
		s.operations.mu.Unlock()
		if err != nil {
			return true
		}
		a = current
	}
	intent := *a.PolicyParameters.NativeIntent
	if intent.Key != a.IdempotencyKey || intent.ConnectorID != a.ConnectorID || intent.Target.Account != a.AccountID || intent.Target.SessionID != a.SessionID || intent.DropType != runtime.DropType {
		s.finishAction(id, "blocked", "", "native intent scope mismatch")
		return true
	}
	executor := srunapi.Executor{Journal: srunapi.Journal{DB: db}, Native: runtime.Client, Read: runtime.Read, Now: now, MaxAge: 30 * time.Second, Authorize: func(c context.Context, _ srunapi.DispatchIntent) error { return s.nativeAuthorization(c, a) }}
	result, stepErr := executor.Step(ctx, intent)
	// Observations are persisted by Executor. Keep uncertain outcomes in the
	// existing queue with a bounded polling interval, without incrementing sends.
	s.operations.mu.Lock()
	current := s.operations.doc.Actions[id]
	if current.Status == "running" {
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
		s.appendAudit(ctx, "enforcement.native_observed", id, result.Delivery+":"+result.Observation)
	}
	return true
}
