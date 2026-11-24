package sharedaccess

import (
	"net"
	"slices"
	"strings"
	"time"

	"proxy-sentinel/internal/policy"
)

const AuthenticatedRouter = "authenticated_router"

// OutletActivity identifies one observed source, even if the capture window
// was incomplete for the separate purpose of counting downstream clients.
type OutletActivity struct {
	MAC       string    `json:"mac"`
	At        time.Time `json:"at"`
	EventID   string    `json:"event_id"`
	OuterVLAN uint16    `json:"outer_vlan,omitempty"`
	VLAN      uint16    `json:"vlan,omitempty"`
}

type RouterProof struct {
	AssessmentID   string `json:"assessment_id"`
	RoleEvidenceID string `json:"role_evidence_id"`
	RuleID         string `json:"rule_id"`
	Account        string `json:"account_id"`
	Session        string `json:"session_id"`
	MAC            string `json:"mac"`
}

// Positive evidence from a particular packet survives loss of unrelated
// packets. Conflicting identity, duplicated content and mixed VLANs do not.
func (w Window) HasRouterProof() bool {
	p, a := w.RouterProof, w.Activity
	if p == nil || a == nil || p.AssessmentID == "" || p.RoleEvidenceID == "" || p.RuleID == "" || p.Account == "" || p.Session == "" || p.MAC != a.MAC || w.MixedClientVLAN || a.At.Before(w.From) || a.At.After(w.To) || !slices.Contains(w.EventIDs, a.EventID) {
		return false
	}
	mac, err := net.ParseMAC(a.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return false
	}
	for _, c := range w.Conflicts {
		if !strings.HasPrefix(c, "capture_interval_incomplete:") && !strings.HasPrefix(c, "capture_unlocated_loss:") && c != "feature_value_limit" {
			return false
		}
	}
	return slices.ContainsFunc(w.Records, func(r RecordRef) bool {
		return r.EventID == a.EventID && r.Source == "handshake-sidecar" && r.InstanceID != ""
	})
}

func routerSessionMatches(w Window, ss []policy.Session) bool {
	for _, s := range ss {
		if s.State(w.Activity.At) != "active" {
			continue
		}
		mac, err := net.ParseMAC(s.MAC)
		if err != nil || mac.String() != w.RouterProof.MAC || s.ID != w.RouterProof.Session || s.AccountID != w.RouterProof.Account {
			return false
		}
	}
	return true
}
