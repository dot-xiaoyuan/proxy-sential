package controlplane

import (
	"context"
	"fmt"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
	"reflect"
	"strings"
)

// PolicyActionParameters identifies the account lease independently from a controller's action ID.
// Controllers advertising account_policy_v1 must revoke only this lease and combine active limits.
type PolicyActionParameters struct {
	SharedReview   *sharedDisconnectBinding `json:"shared_review,omitempty"`
	NativeSelected bool                     `json:"native_selected,omitempty"`
	NativeIntent   *srunapi.DispatchIntent  `json:"native_intent,omitempty"`
	ExecutionID    string                   `json:"execution_id"`
	LeaseID        string                   `json:"lease_id"`
	AccessDomain   string                   `json:"access_domain"`
	RateKbps       int                      `json:"rate_kbps"`
	Template       string                   `json:"template"`
	Operation      string                   `json:"operation"`
}

func (s *Server) processAccountPolicies(now time.Time) {
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ss, err := s.policySessions(ctx, reader, now)
	if err != nil {
		return
	}
	proxyRows, proxyErr := s.proxyRows(ctx)
	sharedRows, sharedErr := s.sharedWindows(ctx, now)
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	if s.operations.lockErr != nil {
		return
	}
	defs := []policy.Definition{}
	for _, p := range s.operations.doc.Policies {
		defs = append(defs, p)
	}
	accounts := map[string]bool{}
	for _, session := range ss {
		if session.AccountID != "" {
			accounts[session.AccountID] = true
		}
	}
	for _, e := range s.operations.doc.PolicyExecutions {
		if e.State == "revoked" || e.State == "recovered" {
			s.releasePolicyActionsLocked(e, now, "system-reconcile")
		}
		accounts[e.AccountID] = true
	}
	for account := range accounts {
		selected, _ := policy.Select(defs, account, ss, now)
		for _, p := range selected {
			id := policy.StableID(p.ID, account)
			e := s.operations.doc.PolicyExecutions[id]
			s.preparePolicyStagesLocked(&e, ss, now)
			in := policy.Input{AccountID: account, Reasons: []string{"risk_evidence_not_evaluated"}}
			if p.Trigger == "quota_exceeded" {
				q := policy.EvaluateQuota(account, ss, p.Limits, now)
				in.Known = q.State != "unknown"
				in.Violated = q.State == "exceeded"
				in.Reasons = q.Reasons
			}
			if p.Trigger == "explicit_proxy" && proxyErr == nil {
				in = proxyprotocol.Input(account, proxyRows, ss, now, time.Duration(p.WindowSeconds)*time.Second, p.Mode)
			}
			if p.Trigger == "shared_access" {
				in = policy.Input{AccountID: account, Reasons: []string{"shared_evidence_unavailable"}}
				if sharedErr == nil {
					in = sharedaccess.Input(account, sharedaccess.AccountResults(account, sharedRows, s.sharedConfig, ss, now, time.Duration(p.WindowSeconds)*time.Second), p.Mode)
				}
			}
			d := policy.Advance(p, e, in, now)
			e = d.Execution
			if e.State == "recovered" {
				s.releasePolicyActionsLocked(e, now, "system-recovery")
			}
			for i := range e.Stages {
				if e.Stages[i].Status == "pending_action" && len(e.Stages[i].ActionIDs) == 0 && in.Known && in.Violated {
					s.createPolicyActionsLocked(&e, i, ss, now)
				}
			}
			s.operations.doc.PolicyExecutions[id] = e
		}
	}
	_ = s.operations.saveLocked()
}

// Reconcile existing continuous limits before deciding whether their next stage
// may run. Newly logged-in sessions must not miss a cycle behind escalation.
func (s *Server) preparePolicyStagesLocked(e *policy.Execution, ss []policy.Session, now time.Time) {
	s.refreshPolicyStagesLocked(e, now)
	if e.State == "revoked" || e.State == "recovered" {
		return
	}
	for i := range e.Stages {
		if i < len(e.Definition.Stages) && e.Definition.Mode == "manual" && e.Definition.Stages[i].Action == "disconnect" && e.Stages[i].Status != "succeeded" && len(e.Stages[i].ApprovedSessionBindings) > 0 {
			if policy.ValidateSessionApproval(e.AccountID, e.Stages[i].ApprovedSessionBindings, ss, now) != nil {
				e.Stages[i].Status = "awaiting_approval"
			}
		}

		if i < len(e.Definition.Stages) && len(e.Stages[i].ActionIDs) > 0 && e.Definition.Stages[i].Action == "rate_limit" {
			s.createPolicyActionsLocked(e, i, ss, now)
		}
	}
}

func (s *Server) refreshPolicyStagesLocked(e *policy.Execution, now time.Time) {
	if e.State == "revoked" || e.State == "recovered" {
		return
	}
	for i := range e.Stages {
		st := &e.Stages[i]
		if len(st.ActionIDs) == 0 || st.Status == "awaiting_approval" {
			continue
		}
		success, failed := 0, 0
		for _, id := range st.ActionIDs {
			a := s.operations.doc.Actions[id]
			switch a.Status {
			case "succeeded":
				success++
			case "failed", "blocked", "cancelled":
				failed++
			}
		}
		switch {
		case success == len(st.ActionIDs):
			st.Status = "succeeded"
			if st.CompletedAt.IsZero() {
				st.CompletedAt = now
				st.CompletedPausedSeconds = e.PausedSeconds
			}
		case success > 0:
			st.Status = "partial_success"
		case failed > 0:
			st.Status = "failed"
		default:
			st.Status = "pending_action"
		}
		if st.Status != "succeeded" {
			st.CompletedAt = time.Time{}
			st.CompletedPausedSeconds = 0
		}
	}
}

func (s *Server) createPolicyActionsLocked(e *policy.Execution, index int, ss []policy.Session, now time.Time) {
	st := &e.Stages[index]
	if e.Definition.Trigger == "shared_access" {
		if e.Definition.Mode != "manual" || index >= len(e.Definition.Stages) || e.Definition.Stages[index].Action != "disconnect" {
			st.Status = "blocked"
			e.Reasons = []string{"shared_manual_disconnect_only"}
			return
		}
		if len(st.ApprovedEvidenceIDs) == 0 || !reflect.DeepEqual(st.ApprovedEvidenceIDs, e.EvidenceIDs) {
			st.Status = "awaiting_approval"
			e.Reasons = []string{"shared_evidence_changed_review_again"}
			return
		}
	}
	if e.Definition.Trigger == "explicit_proxy" {
		if e.Definition.Mode != "manual" {
			st.Status = "blocked"
			e.Reasons = []string{"proxy_automatic_forbidden"}
			return
		}
		if len(st.ApprovedEvidenceIDs) == 0 || !reflect.DeepEqual(st.ApprovedEvidenceIDs, e.EvidenceIDs) {
			st.Status = "awaiting_approval"
			e.Reasons = []string{"proxy_evidence_changed_review_again"}
			return
		}
	}
	stage := e.Definition.Stages[index]
	if e.Definition.Mode == "manual" && stage.Action == "disconnect" {
		if err := policy.ValidateSessionApproval(e.AccountID, st.ApprovedSessionBindings, ss, now); err != nil {
			st.Status = "awaiting_approval"
			e.Reasons = append(e.Reasons, "account_sessions_changed_review_again")
			return
		}
	}

	connector, ok := s.operations.doc.Connectors[stage.ConnectorID]
	if !ok || !connector.Enabled || connector.ActionMapping["account_policy_v1"] != "supported" {
		st.Status = "blocked"
		e.Reasons = append(e.Reasons, "account_policy_controller_unavailable")
		return
	}
	if s.operations.doc.GlobalStop || connector.Mode != "active" || (!connector.ShadowReady && !s.nativeTestStageAllowed(*e, index)) {
		st.Status = "blocked"
		e.Reasons = append(e.Reasons, "shadow_or_emergency_gate")
		return
	}
	if until, err := time.Parse(time.RFC3339Nano, connector.CircuitOpenUntil); err == nil && until.After(now) {
		st.Status = "blocked"
		e.Reasons = append(e.Reasons, "controller_circuit_open")
		return
	}
	native := connector.ActionMapping["account."+stage.Action] != ""
	if !native && (stage.Action == "disable_account" || stage.Action == "notify" || connector.ActionMapping["session."+stage.Action] == "") {
		st.Status = "blocked"
		e.Reasons = append(e.Reasons, "controller_action_unavailable")
		return
	}
	targets := []policy.Session{}
	for _, session := range ss {
		if session.AccountID != e.AccountID || session.State(now) == "ended" || session.State(now) == "absent" {
			continue
		}
		a := policy.Attribute(ss, session.CampusID, session.AccessDomain, session.IP, now)
		if session.State(now) != "active" || a.State != "resolved" || a.AccountID != e.AccountID {
			st.Status = "blocked"
			e.Reasons = append(e.Reasons, "account_identity_uncertain")
			return
		}
		targets = append(targets, session)
	}
	if len(targets) == 0 {
		st.Status = "blocked"
		e.Reasons = append(e.Reasons, "no_confirmed_sessions")
		return
	}
	duration := stage.DurationSeconds
	expiry := time.Time{}
	for _, id := range st.ActionIDs {
		a := s.operations.doc.Actions[id]
		if t, err := time.Parse(time.RFC3339Nano, a.ExpiresAt); err == nil && (expiry.IsZero() || t.Before(expiry)) {
			expiry = t
		}
	}
	if !expiry.IsZero() {
		if !expiry.After(now) {
			return
		}
		duration = int(expiry.Sub(now).Seconds())
		if duration <= 0 {
			return
		}
	}
	if native {
		if len(st.ActionIDs) > 0 {
			return
		}
		targets = []policy.Session{{}}
	}
	known := map[string]bool{}
	for _, id := range st.ActionIDs {
		known[id] = true
	}
	for _, target := range targets {
		completed := false
		if stage.Action == "disconnect" {
			for _, existingID := range st.ActionIDs {
				previous := s.operations.doc.Actions[existingID]
				if previous.Status == "succeeded" && previous.AccountID == e.AccountID && (native || (previous.SessionID == target.ID && previous.CampusID == target.CampusID && previous.PolicyParameters.AccessDomain == target.AccessDomain && previous.IP == target.IP && previous.ActionID == "policy-action-"+policy.StableID(previous.PolicyParameters.LeaseID, target.Source, target.CampusID, target.AccessDomain, target.ID, target.StartedAt.String()))) {
					completed = true
					break
				}
			}
		}
		if completed {
			continue
		}
		key := policy.StableID(st.Key, target.Source, target.CampusID, target.AccessDomain, target.ID, target.StartedAt.String())
		id := "policy-action-" + key
		scope := "session"
		if native {
			scope = "account"
		}
		action := EnforcementAction{ActionID: id, IdempotencyKey: key, ConnectorID: stage.ConnectorID, ActionType: scope + "." + stage.Action, SubjectType: scope, SubjectID: e.AccountID, AccountID: e.AccountID, SessionID: target.ID, CampusID: target.CampusID, IP: target.IP, EndpointID: target.EndpointID, Status: "pending", Mode: "active", DurationSeconds: duration, EvidenceIDs: e.EvidenceIDs, CreatedBy: "policy-engine", CreatedAt: formatDBTime(now), UpdatedAt: formatDBTime(now), PolicyParameters: PolicyActionParameters{ExecutionID: e.ID, LeaseID: st.Key, AccessDomain: target.AccessDomain, RateKbps: stage.RateKbps, Template: stage.Template, Operation: stage.Action}}
		if stage.DurationSeconds > 0 {
			action.ExpiresAt = formatDBTime(now.Add(time.Duration(duration) * time.Second))
		}
		if _, exists := s.operations.doc.Actions[id]; !exists {
			s.operations.doc.Actions[id] = action
		}
		if !known[id] {
			st.ActionIDs = append(st.ActionIDs, id)
			st.Status = "pending_action"
			st.CompletedAt = time.Time{}
			st.CompletedPausedSeconds = 0
		}
	}
}
func (s *Server) releasePolicyActionsLocked(e policy.Execution, now time.Time, actor string) {
	for id, a := range s.operations.doc.Actions {
		if a.PolicyParameters.ExecutionID != e.ID || a.ActionType == "release" {
			continue
		}
		_, nativeConfigured := s.nativeActions[a.ConnectorID]
		native := nativeConfigured || a.PolicyParameters.NativeSelected || a.PolicyParameters.NativeIntent != nil
		if a.Status == "pending" || a.Status == "blocked" || (native && a.Status == "running") {
			a.Status = "cancelled"
			a.NextAttemptAt = ""
			a.UpdatedAt = formatDBTime(now)
			if native {
				a.PolicyParameters.NativeSelected = true
				a.ExpiresAt = ""
				a.LastError = "策略轮次已撤销，停止后续下线；已发送请求可能仍生效"
			}
			s.operations.doc.Actions[id] = a
			continue
		}
		if a.Status != "succeeded" || (a.PolicyParameters.Operation != "rate_limit" && a.PolicyParameters.Operation != "disable_account") {
			continue
		}
		exists := false
		for _, r := range s.operations.doc.Actions {
			if r.ParentActionID == id && r.ActionType == "release" {
				exists = true
				break
			}
		}
		if !exists {
			r := s.newReleaseAction(a, actor, now)
			s.operations.doc.Actions[r.ActionID] = r
		}
	}
}
func validateCurrentPolicySelection(ex policy.Execution, definitions []policy.Definition, sessions []policy.Session, now time.Time) error {
	chosen, _ := policy.Select(definitions, ex.AccountID, sessions, now)
	for _, p := range chosen {
		if p.ID == ex.PolicyID && p.Revision == ex.Definition.Revision && p.Mode == ex.Definition.Mode && p.Mode != "observe" && p.Trigger == ex.Definition.Trigger {
			return nil
		}
	}
	return fmt.Errorf("policy changed, disabled, superseded or exemption matched")
}

func (s *Server) validatePolicyDelivery(a EnforcementAction) error {
	if a.ActionType != "release" && a.PolicyParameters.ExecutionID == "" {
		for _, id := range a.EvidenceIDs {
			if strings.HasPrefix(id, "shared-") {
				return fmt.Errorf("shared access evidence is observation only")
			}
			if strings.HasPrefix(id, "proxy-") {
				return fmt.Errorf("proxy evidence requires manual policy authorization")
			}
		}
	}
	if a.PolicyParameters.ExecutionID == "" || a.ActionType == "release" {
		return nil
	}
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		return fmt.Errorf("identity unavailable")
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ss, err := s.policySessions(ctx, reader, now)
	if err != nil {
		return err
	}
	ex, connector, definitions, err := s.policyDeliveryState(ctx, a)
	if err != nil {
		return err
	}
	if !connector.ShadowReady && (!s.nativeTestAccountAllowed(a.ConnectorID, a.AccountID, a.CampusID, a.PolicyParameters.AccessDomain) || ex.Definition.Mode != "manual" || ex.Definition.Trigger != "shared_access" || a.PolicyParameters.Operation != "disconnect") {
		return fmt.Errorf("shadow admission or scoped manual test authorization required")
	}
	if ex.State == "revoked" || ex.State == "recovered" {
		return fmt.Errorf("policy episode ended")
	}
	if ex.AccountID != a.AccountID {
		return fmt.Errorf("policy action account mismatch")
	}
	if err := validateCurrentPolicySelection(ex, definitions, ss, now); err != nil {
		return err
	}
	if ex.Definition.Trigger == "quota_exceeded" {
		q := policy.EvaluateQuota(a.AccountID, ss, ex.Definition.Limits, now)
		if q.State != "exceeded" {
			return fmt.Errorf("quota violation no longer confirmed")
		}
	} else if ex.Definition.Trigger == "shared_access" {
		if ex.Definition.Mode != "manual" || a.PolicyParameters.Operation != "disconnect" {
			return fmt.Errorf("shared evidence supports manual disconnect only")
		}
		rows, err := s.sharedWindows(ctx, now)
		if err != nil {
			return err
		}
		input := sharedaccess.Input(a.AccountID, sharedaccess.AccountResults(a.AccountID, rows, s.sharedConfig, ss, now, time.Duration(ex.Definition.WindowSeconds)*time.Second), ex.Definition.Mode)
		if !input.Known || !input.Violated {
			return fmt.Errorf("shared evidence expired or identity changed")
		}
		approved := false
		for _, stage := range ex.Stages {
			if stage.Key == a.PolicyParameters.LeaseID && len(stage.ApprovedEvidenceIDs) > 0 && reflect.DeepEqual(stage.ApprovedEvidenceIDs, a.EvidenceIDs) && reflect.DeepEqual(input.EvidenceIDs, a.EvidenceIDs) {
				approved = true
			}
		}
		if !approved {
			return fmt.Errorf("shared evidence requires renewed manual approval")
		}
	} else if ex.Definition.Trigger == "explicit_proxy" {
		if ex.Definition.Mode != "manual" {
			return fmt.Errorf("proxy automatic enforcement forbidden")
		}
		input := s.proxyPolicyInput(ctx, ex.Definition, a.AccountID, ss, now)
		if !input.Known || !input.Violated {
			return fmt.Errorf("proxy evidence expired or identity changed")
		}
		approved := false
		for _, stage := range ex.Stages {
			if stage.Key == a.PolicyParameters.LeaseID && len(stage.ApprovedEvidenceIDs) > 0 && reflect.DeepEqual(stage.ApprovedEvidenceIDs, a.EvidenceIDs) && reflect.DeepEqual(input.EvidenceIDs, a.EvidenceIDs) {
				approved = true
			}
		}
		if !approved {
			return fmt.Errorf("proxy evidence requires renewed manual approval")
		}
	} else {
		return fmt.Errorf("risk evidence unavailable")
	}

	if ex.Definition.Mode == "manual" && (a.PolicyParameters.Operation == "disconnect" || a.ActionType == "disconnect" || strings.HasSuffix(a.ActionType, ".disconnect")) {
		approved := false
		for _, stage := range ex.Stages {
			if stage.Key == a.PolicyParameters.LeaseID && policy.ValidateSessionApproval(a.AccountID, stage.ApprovedSessionBindings, ss, now) == nil {
				approved = true
			}
		}
		if !approved {
			return fmt.Errorf("manual account session confirmation changed")
		}
	}
	found := false
	for _, session := range ss {
		if session.AccountID != a.AccountID || session.State(now) == "ended" || session.State(now) == "absent" {
			continue
		}
		attribution := policy.Attribute(ss, session.CampusID, session.AccessDomain, session.IP, now)
		if session.State(now) != "active" || attribution.State != "resolved" || attribution.AccountID != a.AccountID {
			return fmt.Errorf("account identity changed")
		}
		if a.SubjectType == "account" || (session.ID == a.SessionID && session.IP == a.IP && session.AccessDomain == a.PolicyParameters.AccessDomain && session.CampusID == a.CampusID) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("no matching current session")
	}
	return nil
}
