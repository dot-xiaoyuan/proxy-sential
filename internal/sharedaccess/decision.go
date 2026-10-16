package sharedaccess

import (
	"encoding/json"
	"proxy-sentinel/internal/policy"
	"strconv"
	"time"
)

type ObservationDecision struct {
	IdentityEvidence  []policy.Session `json:"identity_evidence,omitempty"`
	DecisionID        string           `json:"decision_id"`
	ExecutionID       string           `json:"execution_id"`
	PolicyID          string           `json:"policy_id"`
	PolicyRevision    int              `json:"policy_revision"`
	Trigger           string           `json:"trigger"`
	ObservationID     string           `json:"observation_id"`
	EvidenceVersion   string           `json:"evidence_version"`
	AccountID         string           `json:"account_id"`
	IP                string           `json:"ip"`
	CampusID          string           `json:"campus_id"`
	AccessDomain      string           `json:"access_domain"`
	SessionGeneration string           `json:"session_generation"`
	Mode              string           `json:"mode"`
	PlannedAction     string           `json:"planned_action"`
	DeliveryStatus    string           `json:"delivery_status"`
	Result            string           `json:"result"`
	Known             bool             `json:"known"`
	Violated          bool             `json:"violated"`
	EvaluatedAt       time.Time        `json:"evaluated_at"`
	EvidenceExpiresAt time.Time        `json:"evidence_expires_at"`
	Reasons           []string         `json:"reasons"`
	Evidence          Window           `json:"evidence"`
	Attribution       Result           `json:"attribution"`
}

func NewObservationDecision(w Window, r Result, cfg Config, now time.Time) ObservationDecision {
	p := ObservationPolicy()
	state := "insufficient"
	// Current evidence supports AP association only. Until a standard routing /
	// NAT forwarding fact is implemented and independently verified, no caller
	// may manufacture a router-sharing hit from a precomputed basis_present.
	if r.State == "basis_present" {
		r.State = "insufficient"
		r.Reasons = []string{"router_forwarding_not_verified"}
	}
	expires := w.LastObservedAt.Add(cfg.Freshness())
	if w.LastObservedAt.IsZero() || !now.Before(expires) {
		state = "expired"
		r.Reasons = []string{"shared_evidence_expired"}
	}
	version := policy.StableID(w.ID, cfg.ID(), w.RuleVersion, BehaviorRuleVersion)
	// Evidence version changes are audited. Retries and polls keep the same key.
	base := []string{p.ID, strconv.Itoa(p.Revision), r.AccountID, w.CampusID, w.AccessDomain, r.SessionGeneration, version}
	id := policy.StableID(base...)
	execution := ""
	if state == "matched" {
		execution = "shared-observe-" + id
	}
	detail, _ := json.Marshal(r.Reasons)
	id = policy.StableID(id, state, string(detail))
	return ObservationDecision{DecisionID: id, ExecutionID: execution, PolicyID: p.ID, PolicyRevision: p.Revision, Trigger: "shared_access", ObservationID: w.ID, EvidenceVersion: version, AccountID: r.AccountID, IP: w.IP, CampusID: w.CampusID, AccessDomain: w.AccessDomain, SessionGeneration: r.SessionGeneration, Mode: "observe", PlannedAction: "disconnect", DeliveryStatus: "not_sent", Result: state, Known: state == "matched", Violated: state == "matched", EvaluatedAt: now, EvidenceExpiresAt: expires, Reasons: r.Reasons, Evidence: w, Attribution: r}
}
