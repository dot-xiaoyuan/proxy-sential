// Package sharedaccess evaluates scoped shared-access observations independently
// from packet parsers, total risk scores, application names, and device quotas.
package sharedaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/policy"
)

const RuleVersion = "shared-access/v3"

type Source struct {
	SensorID     string `json:"sensor_id"`
	Source       string `json:"source"`
	CampusID     string `json:"campus_id"`
	AccessDomain string `json:"access_domain"`
}
type Config struct {
	SchemaVersion    string   `json:"schema_version,omitempty"`
	FreshnessSeconds int      `json:"freshness_seconds"`
	Version          string   `json:"version"`
	Sources          []Source `json:"sources"`
}

func (c Config) ID() string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

type RecordRef struct {
	EventID    string `json:"event_id"`
	Source     string `json:"source"`
	InstanceID string `json:"collector_instance_id,omitempty"`
}

type Window struct {
	CoverageVerified bool                                `json:"coverage_verified,omitempty"`
	Samples          map[string]map[string]FeatureSample `json:"feature_samples,omitempty"`
	Records          []RecordRef                         `json:"records,omitempty"`
	ID               string                              `json:"id"`
	RuleVersion      string                              `json:"rule_version"`
	IP               string                              `json:"ip"`
	SensorID         string                              `json:"sensor_id"`
	CampusID         string                              `json:"campus_id,omitempty"`
	AccessDomain     string                              `json:"access_domain,omitempty"`
	Sources          []string                            `json:"sources"`
	From             time.Time                           `json:"from"`
	To               time.Time                           `json:"to"`
	LastObservedAt   time.Time                           `json:"last_observed_at"`
	Complete         bool                                `json:"complete"`
	EventIDs         []string                            `json:"event_ids"`
	UAOS             []string                            `json:"ua_os"`
	TTLPaths         []string                            `json:"ttl_paths"`
	TLSStacks        []string                            `json:"tls_stacks"`
	TCPStacks        []string                            `json:"tcp_stacks"`
	DHCPProfiles     []string                            `json:"dhcp_profiles"`
	Conflicts        []string                            `json:"conflicts"`
}
type Result struct {
	Records          []RecordRef `json:"records,omitempty"`
	ID               string      `json:"id"`
	State            string      `json:"state"`
	AccountID        string      `json:"account_id,omitempty"`
	IP               string      `json:"ip"`
	SensorID         string      `json:"sensor_id"`
	CampusID         string      `json:"campus_id,omitempty"`
	AccessDomain     string      `json:"access_domain,omitempty"`
	RuleVersion      string      `json:"rule_version"`
	ConfigVersion    string      `json:"config_version"`
	From             time.Time   `json:"from"`
	To               time.Time   `json:"to"`
	ObservedAt       time.Time   `json:"observed_at"`
	DeviceLowerBound int         `json:"device_lower_bound"`
	QuantityKnown    bool        `json:"quantity_known"`
	Confidence       float64     `json:"confidence"`
	SignalGroups     []string    `json:"signal_groups"`
	Reasons          []string    `json:"reasons"`
	EvidenceIDs      []string    `json:"evidence_ids"`
	EventIDs         []string    `json:"event_ids"`
}

func Evaluate(w Window, cfg Config, ss []policy.Session, now time.Time, lookback time.Duration) Result {
	r := Result{Records: append([]RecordRef{}, w.Records...), ID: w.ID, State: "insufficient", IP: w.IP, SensorID: w.SensorID, RuleVersion: RuleVersion, ConfigVersion: cfg.ID(), From: w.From, To: w.To, ObservedAt: w.LastObservedAt, SignalGroups: []string{}, Reasons: []string{}, EvidenceIDs: []string{w.ID}, EventIDs: append([]string{}, w.EventIDs...)}
	fail := func(reason string) Result { r.Reasons = append(r.Reasons, reason); return r }
	if w.ID == "" || w.RuleVersion != RuleVersion || len(w.EventIDs) == 0 {
		return fail("invalid_shared_evidence")
	}
	if lookback <= 0 || w.From.IsZero() || w.To.Before(w.From) || w.To.After(now) || w.To.Sub(w.From) > lookback || w.LastObservedAt.Before(w.From) || w.LastObservedAt.After(w.To) || w.LastObservedAt.Before(now.Add(-lookback)) {
		return fail("stale_or_invalid_shared_window")
	}
	freshness := time.Duration(cfg.FreshnessSeconds) * time.Second
	if freshness <= 0 {
		freshness = 3 * time.Minute
	}
	if now.Sub(w.LastObservedAt) > freshness {
		return fail("stale_or_invalid_shared_window")
	}
	if len(w.Conflicts) > 0 {
		r.Reasons = append(r.Reasons, w.Conflicts...)
		return fail("shared_observation_conflict")
	}
	if ip, err := netip.ParseAddr(w.IP); err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return fail("invalid_shared_ip")
	}
	if w.CampusID == "" || w.AccessDomain == "" {
		return fail("missing_access_scope")
	}
	if cfg.Version == "" || w.SensorID == "" || len(w.Sources) == 0 {
		return fail("unregistered_shared_source")
	}
	for _, observed := range w.Sources {
		found := false
		for _, source := range cfg.Sources {
			if source.SensorID != w.SensorID || source.Source != observed {
				continue
			}
			if source.CampusID == "" || source.AccessDomain == "" {
				return fail("missing_access_scope")
			}
			if found || r.CampusID != "" && (r.CampusID != source.CampusID || r.AccessDomain != source.AccessDomain) {
				return fail("ambiguous_shared_source_scope")
			}
			found = true
			r.CampusID = source.CampusID
			r.AccessDomain = source.AccessDomain
		}
		if !found {
			return fail("unregistered_shared_source")
		}
	}
	if w.CampusID != "" && w.CampusID != r.CampusID || w.AccessDomain != "" && w.AccessDomain != r.AccessDomain {
		return fail("shared_source_scope_mismatch")
	}
	// Check all identity validity boundaries inside the observation window. Merely
	// comparing its endpoints would miss an IP that changed owners and changed back.
	selected := []policy.Session{}
	points := []time.Time{w.From, w.To, w.LastObservedAt}
	for _, s := range ss {
		if s.IP != w.IP || s.CampusID != r.CampusID || s.AccessDomain != r.AccessDomain {
			continue
		}
		selected = append(selected, s)
		points = append(points, s.StartedAt, s.EndedAt)
		period := s.HeartbeatSeconds
		if period <= 0 {
			period = s.ReconcileSeconds
		}
		for _, at := range append(append([]time.Time{}, s.Confirmations...), s.ConfirmedAt) {
			points = append(points, at, at.Add(time.Duration(3*period)*time.Second))
		}
		for _, coverage := range s.SourceCoverage {
			points = append(points, coverage.From, coverage.To)
		}
	}
	account := ""
	generation := ""
	for _, point := range points {
		if point.Before(w.From) || point.After(w.To) {
			continue
		}
		a := policy.Attribute(selected, r.CampusID, r.AccessDomain, w.IP, point)
		if a.State != "resolved" {
			return fail("shared_identity_unknown_or_conflicting")
		}
		if account != "" && a.AccountID != account {
			return fail("shared_identity_changed_within_window")
		}
		// Bind the window to an unchanged set of authentication generations.
		// Account equality alone cannot distinguish sequential device logins.
		keys := []string{}
		for _, session := range selected {
			if session.State(point) == "active" {
				if session.ID == "" {
					return fail("shared_session_generation_missing")
				}
				raw, _ := json.Marshal([]string{session.ID, session.Source, session.StartedAt.UTC().Format(time.RFC3339Nano)})
				keys = append(keys, string(raw))
			}
		}
		sort.Strings(keys)
		raw, _ := json.Marshal(keys)
		current := string(raw)
		if generation != "" && generation != current {
			return fail("shared_session_generation_changed_within_window")
		}
		generation = current
		account = a.AccountID
	}
	if account == "" {
		return fail("shared_identity_unknown_or_conflicting")
	}
	r.AccountID = account
	quota := policy.EvaluateQuota(account, selected, policy.Limits{}, w.LastObservedAt)
	r.DeviceLowerBound = quota.Total
	r.QuantityKnown = quota.Total > 0
	ua := diversity(w.UAOS) > 1
	ttl := diversity(w.TTLPaths) > 1
	tls := diversity(w.TLSStacks) > 1
	tcp := diversity(w.TCPStacks) > 1
	device := diversity(w.DHCPProfiles) > 1
	if ua {
		r.SignalGroups = append(r.SignalGroups, "ua_os")
	}
	if ttl {
		r.SignalGroups = append(r.SignalGroups, "ttl_path")
	}
	if tls {
		r.SignalGroups = append(r.SignalGroups, "tls_stack")
	}
	if tcp {
		r.SignalGroups = append(r.SignalGroups, "tcp_stack")
	}
	if device {
		r.SignalGroups = append(r.SignalGroups, "dhcp_stack")
	}
	if r.DeviceLowerBound >= 2 {
		r.SignalGroups = append(r.SignalGroups, "confirmed_same_exit_endpoints")
	}
	if !w.Complete {
		return fail("incomplete_shared_observation_window")
	}
	if !r.QuantityKnown {
		r.Reasons = append(r.Reasons, "shared_device_quantity_unknown")
	}

	if ua && ttl && (tls || tcp || device) || device && ttl && (tls || tcp) || r.DeviceLowerBound >= 2 && (ua || ttl || device || tcp) {
		for _, group := range []struct {
			family  string
			values  []string
			diverse bool
		}{
			{"ua_os", w.UAOS, ua}, {"ttl_path", w.TTLPaths, ttl}, {"tls_stack", w.TLSStacks, tls}, {"tcp_stack", w.TCPStacks, tcp}, {"dhcp_stack", w.DHCPProfiles, device},
		} {
			if group.diverse && !w.repeatedTogether(group.family, group.values) {
				return fail("shared_features_lack_repeated_coexistence")
			}
		}
		r.State = "basis_present"
		r.Confidence = 0.70
		if r.DeviceLowerBound >= 2 {
			r.Confidence = 0.90
		}
		r.Reasons = append(r.Reasons, "corroborated_shared_access_basis_requires_review")
		return r
	}
	if ua || ttl || device {
		return fail("insufficient_independent_shared_signals")
	}
	r.State = "not_matched"
	r.Confidence = 0.70
	r.Reasons = append(r.Reasons, "no_shared_basis_in_complete_window")
	return r
}
func diversity(values []string) int {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && value != "unknown" {
			set[value] = true
		}
	}
	return len(set)
}

// Results must cover the account's relevant access scopes. Callers add an
// insufficient result for every scope without a complete, fresh observation.
func Input(account string, results []Result, mode string) policy.Input {
	in := policy.Input{AccountID: account, Reasons: []string{}, EvidenceIDs: []string{}}
	if mode != "observe" && mode != "manual" {
		in.Reasons = []string{"shared_access_automatic_forbidden"}
		return in
	}
	negative, unknown := false, false
	seen := map[string]bool{}
	for _, r := range results {
		if r.State == "insufficient" && (r.AccountID == "" || r.AccountID == account) {
			unknown = true
		}
		if r.AccountID != account {
			continue
		}
		if r.State == "basis_present" {
			in.Known = true
			in.Violated = true
			for _, id := range r.EvidenceIDs {
				if !seen[id] {
					in.EvidenceIDs = append(in.EvidenceIDs, id)
					seen[id] = true
				}
			}
		}
		if r.State == "not_matched" {
			negative = true
		}
	}
	sort.Strings(in.EvidenceIDs)
	if in.Violated {
		in.Reasons = []string{"corroborated_shared_access_basis_requires_review"}
		return in
	}
	if negative && !unknown {
		in.Known = true
		in.Reasons = []string{"no_shared_basis_in_complete_window"}
	} else {
		in.Reasons = []string{"shared_evidence_insufficient_or_expired"}
	}
	return in
}
