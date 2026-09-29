package controlplane

import (
	"context"
	"fmt"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/store"
	"time"
)

func (s *Server) processProxyProtocol(ctx context.Context, now time.Time) (bool, error) {
	if s.proxyConfig.Version == "" || s.proxyResults == nil {
		return false, nil
	}
	source, ok := s.reader.(proxyprotocol.EventSource)
	if !ok {
		return false, fmt.Errorf("proxy source unavailable")
	}
	state, err := s.proxyResults.State(ctx)
	if err != nil {
		return false, err
	}
	if state.To.IsZero() || state.ConfigID != s.proxyConfig.ID() {
		state = proxyprotocol.ScanState{From: now.Add(-7 * 24 * time.Hour), To: now, ConfigID: s.proxyConfig.ID()}
	}
	events, err := source.ScanProxyEvents(ctx, proxyprotocol.Scan{From: state.From, To: state.To, After: state.After, Limit: 1000})
	if err != nil {
		return false, err
	}
	var sessions []policy.Session
	if reader, ok := s.reader.(store.PolicyIdentityReader); ok {
		sessions, err = s.policySessions(ctx, reader, now)
		if err != nil {
			return false, err
		}
	}
	results := []proxyprotocol.Result{}
	for _, e := range events {
		result := proxyprotocol.Attribute(proxyprotocol.Evaluate(e, s.proxyConfig), sessions)
		results = append(results, result)
		state.After = proxyprotocol.EventCursor(e)
	}
	if len(events) == 0 {
		state.To = time.Time{}
		state.After = proxyprotocol.Cursor{}
	}
	if err = s.proxyResults.Commit(ctx, results, state); err != nil {
		return false, err
	}
	return len(events) > 0, nil
}
func (s *Server) runProxyProtocol(ctx context.Context) {
	delay := time.Duration(0)
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		batch, cancel := context.WithTimeout(ctx, 15*time.Second)
		more, err := s.processProxyProtocol(batch, time.Now().UTC())
		cancel()
		delay = 15 * time.Second
		if more && err == nil {
			delay = 100 * time.Millisecond
		}
		if err != nil {
			s.appendAudit(ctx, "proxy_protocol.process", "batch", "failed: "+err.Error())
			delay = 30 * time.Second
		}
	}
}
func (s *Server) proxyRows(ctx context.Context) ([]proxyprotocol.Result, error) {
	if s.proxyConfig.Version == "" || s.proxyResults == nil {
		return []proxyprotocol.Result{}, nil
	}
	rows, err := s.proxyResults.Query(ctx, "", time.Now().Add(-7*24*time.Hour), 10001)
	if err != nil {
		return nil, err
	}
	if len(rows) > 10000 {
		return nil, fmt.Errorf("proxy evidence window exceeds safe query bound")
	}
	out := []proxyprotocol.Result{}
	for _, r := range rows {
		if r.ConfigVersion == s.proxyConfig.ID() {
			out = append(out, r)
		}
	}
	return out, nil
}
func (s *Server) proxyPolicyInput(ctx context.Context, p policy.Definition, account string, ss []policy.Session, now time.Time) policy.Input {
	rows, err := s.proxyRows(ctx)
	if err != nil {
		return policy.Input{AccountID: account, Reasons: []string{"proxy_evidence_unavailable"}}
	}
	return proxyprotocol.Input(account, rows, ss, now, time.Duration(p.WindowSeconds)*time.Second, p.Mode)
}
func (s *Server) proxyEvidence(ctx context.Context, ip string, limit int) ([]evidence.Evidence, error) {
	out := []evidence.Evidence{}
	if s.proxyConfig.Version == "" || s.proxyResults == nil {
		return out, nil
	}
	rows, err := s.proxyResults.Query(ctx, ip, time.Now().Add(-7*24*time.Hour), limit)
	if err != nil {
		return nil, err
	}
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		return nil, fmt.Errorf("identity reader unavailable")
	}
	ss, err := s.policySessions(ctx, reader, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.ConfigVersion != s.proxyConfig.ID() {
			continue
		}
		r = proxyprotocol.Attribute(r, ss)
		out = append(out, evidence.Evidence{EvidenceID: r.ID, IP: r.IP, Type: "proxy_protocol_transaction", SubjectType: "ip", SubjectID: r.IP, AccountID: r.Attribution.AccountID, Window: "7d", Score: 0, Confidence: r.Confidence, Severity: "info", Reason: r.Reason, Samples: r.EventIDs, CreatedAt: r.ObservedAt.Format(time.RFC3339Nano), ProxyProtocol: &r})
	}
	return out, nil
}
