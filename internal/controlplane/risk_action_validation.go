package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

func currentRiskObservation(stamp, window string, now time.Time) bool {
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || at.After(now) || strings.TrimSpace(window) == "" {
		return false
	}
	duration, err := time.ParseDuration(window)
	if err != nil {
		_, duration, err = store.NormalizeActivityWindow(window)
	}
	return err == nil && duration > 0 && at.After(now.Add(-duration))
}

// Only current, referenced evidence can support a queued risk action. A newer
// unrelated rule in the IP's evidence history cannot revive the admitted proof.
func riskActionProofBlockers(snapshot risk.Snapshot, items []evidence.Evidence, approvedIDs []string, now time.Time) []string {
	blockers := []string{}
	if !currentRiskObservation(snapshot.UpdatedAt, snapshot.Window, now) {
		blockers = append(blockers, "risk_snapshot_not_current")
	}
	currentIDs := map[string]bool{}
	for _, id := range snapshot.EvidenceIDs {
		currentIDs[id] = true
	}
	valid := map[string]bool{}
	strongRule := false
	for _, item := range items {
		if !currentIDs[item.EvidenceID] || !slices.Contains(approvedIDs, item.EvidenceID) {
			continue
		}
		if item.IP != snapshot.IP || item.AccountID != "" && item.AccountID != snapshot.AccountID || item.EndpointID != "" && item.EndpointID != snapshot.EndpointID {
			continue
		}
		if item.SubjectType == "account" && item.SubjectID != snapshot.AccountID || item.SubjectType == "endpoint" && item.SubjectID != snapshot.EndpointID || item.SubjectType == "ip" && item.SubjectID != "" && item.SubjectID != snapshot.IP {
			continue
		}
		if !currentRiskObservation(item.CreatedAt, item.Window, now) {
			continue
		}
		valid[item.EvidenceID] = true
		if item.Type == "vpn_proxy_rule_match" && item.Confidence >= .90 {
			strongRule = true
		}
	}
	complete := len(approvedIDs) > 0
	for _, id := range approvedIDs {
		if !valid[id] {
			complete = false
		}
	}
	if !complete {
		blockers = append(blockers, "risk_evidence_not_current")
	}
	strong := strongRule && (snapshot.DetectionBasis == "" || snapshot.DetectionBasis == "explicit_tunnel")
	if snapshot.DetectionBasis == "shared_device_divergence" && len(snapshot.IndependentSignalGroups) >= 2 && complete {
		strong = true
	}
	if !strong {
		blockers = append(blockers, "strong_detection_basis_required")
	}
	return blockers
}

func (s *Server) currentRiskActionSession(ctx context.Context, snapshot risk.Snapshot, requiredID string, now time.Time) (policy.Session, error) {
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok || snapshot.AccountID == "" || snapshot.EndpointID == "" {
		return policy.Session{}, fmt.Errorf("authoritative identity unavailable")
	}
	ss, err := s.policySessions(ctx, reader, now)
	if err != nil {
		return policy.Session{}, err
	}
	var selected policy.Session
	for _, session := range ss {
		if session.AccountID != snapshot.AccountID || session.EndpointID != snapshot.EndpointID || session.IP != snapshot.IP || requiredID != "" && session.ID != requiredID || session.State(now) != "active" {
			continue
		}
		attribution := policy.AttributeForSession(ss, session, now)
		if attribution.State != "resolved" || attribution.AccountID != snapshot.AccountID {
			return policy.Session{}, fmt.Errorf("current account attribution conflicts")
		}
		if selected.ID != "" && selected.ID != session.ID {
			return policy.Session{}, fmt.Errorf("multiple current sessions require explicit selection")
		}
		selected = session
	}
	if selected.ID == "" {
		return policy.Session{}, fmt.Errorf("matching registered current session unavailable")
	}
	profile, found, err := s.reader.GetEndpointIdentity(ctx, snapshot.EndpointID, store.Query{Limit: 100})
	if err != nil {
		return policy.Session{}, err
	}
	if found {
		for _, session := range profile.Sessions {
			if session.SessionID == selected.ID && session.Source == selected.Source && session.AccountID == selected.AccountID && session.EndpointID == selected.EndpointID && session.IP == selected.IP && session.IdentityConfidence >= .8 {
				return selected, nil
			}
		}
	}
	return policy.Session{}, fmt.Errorf("current identity confidence below required threshold")
}

func (s *Server) currentRiskActionCase(ctx context.Context, id string) (RiskCase, error) {
	if s.operations.db != nil {
		var raw []byte
		err := s.operations.db.QueryRowContext(ctx, `SELECT to_jsonb(c)||jsonb_build_object('ip',coalesce(host(c.ip),''),'nas_ip',coalesce(host(c.nas_ip),'')) FROM risk_cases c WHERE case_id=$1`, id).Scan(&raw)
		if err != nil {
			return RiskCase{}, err
		}
		var item RiskCase
		err = json.Unmarshal(raw, &item)
		return item, err
	}
	if err := s.lockActionPrecheckDocument(ctx); err != nil {
		return RiskCase{}, err
	}
	item, ok := s.operations.doc.Cases[id]
	s.operations.mu.Mutex.Unlock()
	if !ok {
		return RiskCase{}, sql.ErrNoRows
	}
	return item, nil
}

func (s *Server) validateRiskActionDeliveryContext(ctx context.Context, a EnforcementAction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	until, parseErr := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if parseErr != nil || !until.After(now) {
		return fmt.Errorf("risk action expired or lacks a valid expiry")
	}
	item, err := s.currentRiskActionCase(ctx, a.CaseID)
	if err != nil {
		return fmt.Errorf("current risk case unavailable: %w", err)
	}
	if item.Status == "closed" || item.Status == "resolved" || item.Disposition == "benign" || item.Disposition == "false_positive" || item.Disposition == "needs_more_data" || item.IdentityConflict || item.IdentityBlocker != "" {
		return fmt.Errorf("current risk case is not actionable")
	}
	if item.IP != a.IP || item.AccountID != a.AccountID || item.EndpointID != a.EndpointID || item.AuthSessionID == "" || item.AuthSessionID != a.SessionID || item.CampusID != "" && item.CampusID != a.CampusID {
		return fmt.Errorf("risk case identity changed")
	}
	snapshot, err := s.reader.GetIPRisk(ctx, a.IP)
	if err != nil {
		return err
	}
	if snapshot.IP != a.IP || snapshot.AccountID != a.AccountID || snapshot.EndpointID != a.EndpointID {
		return fmt.Errorf("current risk identity changed")
	}
	if snapshot.Score < 90 || snapshot.Confidence < .90 || (snapshot.Level != "high" && snapshot.Level != "confirmed") || snapshot.ReviewStatus == "benign" || snapshot.ReviewStatus == "false_positive" || snapshot.ReviewStatus == "needs_more_data" {
		return fmt.Errorf("current risk no longer supports punishment")
	}
	events, err := s.reader.GetIPEvidence(ctx, a.IP, 100)
	if err != nil {
		return err
	}
	now = time.Now().UTC()
	if blockers := riskActionProofBlockers(snapshot, events, a.EvidenceIDs, now); len(blockers) > 0 {
		return fmt.Errorf("current risk proof unavailable: %s", strings.Join(blockers, ", "))
	}
	if _, err = s.currentRiskActionSession(ctx, snapshot, a.SessionID, now); err != nil {
		return err
	}
	if exception, applyErr := s.exceptions.apply(ctx, &snapshot, a.CampusID); applyErr != nil {
		return applyErr
	} else if exception != nil {
		return fmt.Errorf("current risk exception applied")
	}
	exceptions, err := s.exceptions.list(ctx, true)
	if err != nil {
		return err
	}
	if matchEvidenceException(exceptions, events, a.CampusID) != nil {
		return fmt.Errorf("current evidence exception applied")
	}
	return ctx.Err()
}
