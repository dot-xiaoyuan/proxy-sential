package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

type riskActionReplayReader struct {
	store.Reader
	snapshot           risk.Snapshot
	evidence           []evidence.Evidence
	sessions           []policy.Session
	identityConfidence float64
}

func TestQueuedRiskActionStopsBeforeTransportAndKeepsRecovery(t *testing.T) {
	for _, mode := range []string{"current", "downgraded", "release"} {
		t.Run(mode, func(t *testing.T) {
			s, r, a := riskActionReplay(t)
			changeRiskActionReplay(s, r, &a, mode)
			var calls atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"action_id":"isolated-remote","status":"completed"}`))
			}))
			defer remote.Close()
			s.actionMasterKey = []byte("isolated-replay-master-key-123456")
			secret, err := s.encryptConnectorSecret("isolated-controller-secret")
			if err != nil {
				t.Fatal(err)
			}
			s.operations.doc.Connectors[a.ConnectorID] = ActionConnector{ConnectorID: a.ConnectorID, Mode: "active", Enabled: true, EndpointURL: remote.URL, EncryptedSecret: secret}
			a.IdempotencyKey = "isolated-" + mode
			s.operations.doc.Actions[a.ActionID] = a
			s.deliverAction(a.ActionID, false)
			got := s.operations.doc.Actions[a.ActionID]
			if mode == "downgraded" {
				if calls.Load() != 0 || got.Status != "blocked" {
					t.Fatalf("changed risk reached controller: calls=%d status=%s", calls.Load(), got.Status)
				}
			} else if calls.Load() != 1 || got.Status != "succeeded" {
				t.Fatalf("valid action or recovery broken: calls=%d status=%s error=%s", calls.Load(), got.Status, got.LastError)
			}
		})
	}
}

func (r *riskActionReplayReader) GetIPRisk(context.Context, string) (risk.Snapshot, error) {
	return r.snapshot, nil
}
func (r *riskActionReplayReader) GetIPEvidence(context.Context, string, int) ([]evidence.Evidence, error) {
	return r.evidence, nil
}
func (r *riskActionReplayReader) ListPolicySessions(context.Context, time.Time) ([]policy.Session, error) {
	return r.sessions, nil
}
func (r *riskActionReplayReader) GetEndpointIdentity(context.Context, string, store.Query) (store.EndpointIdentityProfile, bool, error) {
	rows := []store.AccountSession{}
	for _, v := range r.sessions {
		ended := ""
		if !v.EndedAt.IsZero() {
			ended = v.EndedAt.Format(time.RFC3339Nano)
		}
		rows = append(rows, store.AccountSession{SessionID: v.ID, AccountID: v.AccountID, EndpointID: v.EndpointID, IP: v.IP, Source: v.Source, StartedAt: v.StartedAt.Format(time.RFC3339Nano), EndedAt: ended, LastConfirmedAt: v.ConfirmedAt.Format(time.RFC3339Nano), HeartbeatSeconds: v.HeartbeatSeconds, IdentityConfidence: r.identityConfidence})
	}
	return store.EndpointIdentityProfile{Sessions: rows}, true, nil
}

func riskActionReplay(t *testing.T) (*Server, *riskActionReplayReader, EnforcementAction) {
	t.Helper()
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	r := &riskActionReplayReader{snapshot: risk.Snapshot{IP: "192.0.2.82", AccountID: "account", EndpointID: "endpoint", Score: 96, Confidence: .96, Level: "high", Window: "10m", UpdatedAt: stamp, EvidenceIDs: []string{"risk-proof"}, DetectionBasis: "explicit_tunnel"}, evidence: []evidence.Evidence{{EvidenceID: "risk-proof", IP: "192.0.2.82", Type: "vpn_proxy_rule_match", Confidence: .96, Window: "10m", CreatedAt: stamp}}, sessions: []policy.Session{{ID: "session", AccountID: "account", EndpointID: "endpoint", IP: "192.0.2.82", Source: "radius", SensorID: "test-source", CampusID: "test-campus", AccessDomain: "test-nas", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, HeartbeatSeconds: 60}}}
	s.reader = r
	r.identityConfidence = .95
	s.identitySources = []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: "radius", SensorID: "test-source", CampusID: "test-campus", AccessDomain: "test-nas"}, IntervalSeconds: 60}}
	s.operations.doc.Cases["risk-case"] = RiskCase{CaseID: "risk-case", IP: r.snapshot.IP, AccountID: "account", EndpointID: "endpoint", AuthSessionID: "session", CampusID: "test-campus", Status: "investigating"}
	a := EnforcementAction{ActionID: "risk-action", CaseID: "risk-case", ConnectorID: "legacy", ActionType: "disconnect", IP: r.snapshot.IP, AccountID: "account", EndpointID: "endpoint", SessionID: "session", CampusID: "test-campus", EvidenceIDs: []string{"risk-proof"}, Status: "pending", Mode: "active", ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano)}
	return s, r, a
}

func changeRiskActionReplay(s *Server, r *riskActionReplayReader, a *EnforcementAction, mode string) {
	now := time.Now().UTC()
	c := s.operations.doc.Cases[a.CaseID]
	switch mode {
	case "downgraded":
		r.snapshot.Score = 59
		r.snapshot.Level = "suspicious"
	case "low_confidence":
		r.snapshot.Confidence = .5
	case "old_snapshot":
		r.snapshot.UpdatedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
	case "future_snapshot":
		r.snapshot.UpdatedAt = now.Add(time.Hour).Format(time.RFC3339Nano)
	case "bad_snapshot_time":
		r.snapshot.UpdatedAt = "invalid"
	case "bad_window":
		r.snapshot.Window = "0s"
	case "missing_window":
		r.snapshot.Window = ""
	case "expired_action":
		a.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	case "invalid_action_expiry":
		a.ExpiresAt = "invalid"
	case "old_evidence":
		r.evidence[0].CreatedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
	case "future_evidence":
		r.evidence[0].CreatedAt = now.Add(time.Hour).Format(time.RFC3339Nano)
	case "missing_evidence":
		r.evidence = nil
	case "missing_action_evidence":
		a.EvidenceIDs = nil
	case "other_ip":
		r.evidence[0].IP = "192.0.2.83"
	case "other_account":
		r.evidence[0].AccountID = "other"
	case "replaced_evidence":
		r.snapshot.EvidenceIDs = []string{"new-proof"}
	case "unreferenced_strong_rule":
		r.snapshot.DetectionBasis = ""
		r.evidence[0].Confidence = .4
		r.evidence = append(r.evidence, evidence.Evidence{EvidenceID: "unrelated", IP: a.IP, Type: "vpn_proxy_rule_match", Confidence: 1, Window: "10m", CreatedAt: now.Format(time.RFC3339Nano)})
	case "case_closed":
		c.Status = "closed"
	case "case_benign":
		c.Disposition = "benign"
	case "case_needs_more_data":
		c.Disposition = "needs_more_data"
	case "identity_blocked":
		c.IdentityBlocker = "归属冲突"
	case "case_owner_changed":
		c.AccountID = "other"
	case "missing_case":
		delete(s.operations.doc.Cases, a.CaseID)
		return
	case "session_changed":
		r.sessions[0].ID = "new-session"
	case "stale_session":
		r.sessions[0].ConfirmedAt = now.Add(-time.Hour)
	case "future_session":
		r.sessions[0].StartedAt = now.Add(time.Hour)
	case "future_confirmation":
		r.sessions[0].ConfirmedAt = now.Add(time.Hour)
	case "ended_session":
		r.sessions[0].EndedAt = now.Add(-time.Second)
	case "conflicting_session":
		other := r.sessions[0]
		other.ID = "other-session"
		other.AccountID = "other"
		r.sessions = append(r.sessions, other)
	case "unregistered_source":
		s.identitySources = nil
	case "low_identity_confidence":
		r.identityConfidence = .5
	case "snapshot_owner_changed":
		r.snapshot.AccountID = "other"
	case "release":
		a.ActionType = "release"
		r.snapshot.Score = 0
		r.evidence = nil
		r.sessions = nil
		c.Status = "closed"
	}
	s.operations.doc.Cases[a.CaseID] = c
}

func TestQueuedRiskActionCannotBorrowProofWithoutOriginalEvidenceIDs(t *testing.T) {
	s, r, a := riskActionReplay(t)
	changeRiskActionReplay(s, r, &a, "missing_action_evidence")
	if s.validatePolicyDelivery(a) == nil {
		t.Fatal("queued intent without evidence IDs borrowed current proof")
	}
}

func TestRiskActionPreservesIdentityConfidenceGate(t *testing.T) {
	s, r, a := riskActionReplay(t)
	changeRiskActionReplay(s, r, &a, "low_identity_confidence")
	if s.validatePolicyDelivery(a) == nil {
		t.Fatal("registered but low-confidence identity was actionable")
	}
}

func TestRiskActionDeliveryRechecksCurrentEvidenceAndIdentity(t *testing.T) {
	for _, mode := range []string{"current", "downgraded", "low_confidence", "old_snapshot", "future_snapshot", "bad_snapshot_time", "bad_window", "missing_window", "expired_action", "invalid_action_expiry", "old_evidence", "future_evidence", "missing_evidence", "other_ip", "other_account", "replaced_evidence", "unreferenced_strong_rule", "case_closed", "case_benign", "case_needs_more_data", "identity_blocked", "case_owner_changed", "missing_case", "session_changed", "stale_session", "future_session", "future_confirmation", "ended_session", "conflicting_session", "unregistered_source", "snapshot_owner_changed", "release"} {
		t.Run(mode, func(t *testing.T) {
			s, r, a := riskActionReplay(t)
			changeRiskActionReplay(s, r, &a, mode)
			err := s.validatePolicyDelivery(a)
			allowed := mode == "current" || mode == "release"
			if (err == nil) != allowed {
				t.Fatalf("delivery allowed=%v want=%v error=%v", err == nil, allowed, err)
			}
		})
	}
}

func TestRiskActionAdmissionRequiresFreshProofAndRegisteredSession(t *testing.T) {
	for _, mode := range []string{"current", "old_snapshot", "future_snapshot", "old_evidence", "unreferenced_strong_rule", "stale_session", "future_session", "conflicting_session", "unregistered_source"} {
		t.Run(mode, func(t *testing.T) {
			s, r, a := riskActionReplay(t)
			changeRiskActionReplay(s, r, &a, mode)
			s.operations.doc.Connectors["legacy"] = ActionConnector{ConnectorID: "legacy", Mode: "shadow", Enabled: true}
			req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"case_id":"risk-case","connector_id":"legacy","action_type":"disconnect","ip":"192.0.2.82"}`))
			req.Header.Set("Idempotency-Key", "replay-"+mode)
			w := httptest.NewRecorder()
			s.handleExecuteAction(w, req)
			var got EnforcementAction
			decodeResponse(t, w, http.StatusAccepted, &got)
			if mode == "current" {
				if got.Status != "shadow" || got.SessionID != "session" {
					t.Fatalf("valid current proof blocked: %+v", got)
				}
			} else if got.Status != "blocked" {
				t.Fatalf("stale or untrusted proof admitted: %+v", got)
			}
		})
	}
}
