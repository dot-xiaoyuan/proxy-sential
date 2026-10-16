package sharedaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"proxy-sentinel/internal/policy"
	"time"
)

const ObservationPolicyID = "builtin:shared-access-observe"

type IdentityMapping struct {
	HealthBridgeID       string    `json:"health_bridge_id,omitempty"`
	SensorID             string    `json:"sensor_id"`
	CampusID             string    `json:"campus_id"`
	AccessDomain         string    `json:"access_domain"`
	Source               string    `json:"identity_source"`
	IdentitySensorID     string    `json:"identity_sensor_id"`
	IdentityCampusID     string    `json:"identity_campus_id"`
	IdentityAccessDomain string    `json:"identity_access_domain"`
	ValidFrom            time.Time `json:"valid_from"`
	ValidUntil           time.Time `json:"valid_until"`
}

func stableObservationID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func ObservationPolicy() policy.Definition {
	return policy.Definition{ID: ObservationPolicyID, Name: "共享确认记录", Enabled: true, Mode: "observe", Trigger: "shared_access", WindowSeconds: 600, Revision: 2, Stages: []policy.Stage{{Action: "disconnect"}}}
}

func (c Config) Mapping(w Window) (IdentityMapping, error) {
	var selected IdentityMapping
	count := 0
	for _, m := range c.IdentityMappings {
		if m.SensorID == w.SensorID && m.CampusID == w.CampusID && m.AccessDomain == w.AccessDomain && !w.From.Before(m.ValidFrom) && w.To.Before(m.ValidUntil) {
			selected = m
			count++
		}
	}
	if count != 1 {
		return selected, fmt.Errorf("shared_identity_mapping_unavailable")
	}
	return selected, nil
}

// Mapping only affects this evaluation's copies. Raw facts keep both original
// scopes, and only the explicitly registered source and sensor may participate.
func EvaluateObservation(w Window, cfg Config, sessions []policy.Session, now time.Time) Result {
	fail := func(reason string) Result {
		return Result{ID: w.ID, State: "insufficient", IP: w.IP, SensorID: w.SensorID, CampusID: w.CampusID, AccessDomain: w.AccessDomain, RuleVersion: RuleVersion, ConfigVersion: cfg.ID(), From: w.From, To: w.To, ObservedAt: w.LastObservedAt, Reasons: []string{reason}, EvidenceIDs: []string{w.ID}, Records: w.Records, EventIDs: w.EventIDs}
	}
	m, err := cfg.Mapping(w)
	if err != nil {
		return fail(err.Error())
	}
	if len(w.Conflicts) > 0 {
		result := fail("shared_observation_conflict")
		result.Reasons = append(append([]string{}, w.Conflicts...), result.Reasons...)
		return result
	}
	if !w.Complete || !w.CoverageVerified {
		return fail("incomplete_shared_observation_window")
	}
	if w.StrongAnchor == "" || w.DeviceLowerBound < 2 {
		return fail("confirmed_shared_observation_required")
	}
	selected := []policy.Session{}
	for _, s := range sessions {
		if s.Source != m.Source || s.SensorID != m.IdentitySensorID || s.CampusID != m.IdentityCampusID || s.AccessDomain != m.IdentityAccessDomain || s.IP != w.IP {
			continue
		}
		s.CampusID, s.AccessDomain = w.CampusID, w.AccessDomain
		selected = append(selected, s)
	}
	result := Evaluate(w, cfg, selected, now, 10*time.Minute)
	if result.State == "basis_present" && (w.StrongAnchor == "" || !w.CoverageVerified || w.DeviceLowerBound < 2) {
		result.State = "insufficient"
		result.Reasons = []string{"confirmed_shared_observation_required"}
	}
	// EasyMesh proves association with an AP, not routing/NAT forwarding.
	// No current collector supplies verified forwarding evidence. Keep account
	// attribution available for review, but never turn association into a hit.
	if result.State == "basis_present" {
		result.State = "insufficient"
		result.Reasons = []string{"router_forwarding_not_verified"}
	}
	return result
}
