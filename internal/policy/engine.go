package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type Scope struct {
	Accounts    []string `json:"accounts"`
	Groups      []string `json:"groups"`
	Products    []string `json:"products"`
	Campuses    []string `json:"campuses"`
	VLANs       []string `json:"vlans"`
	CIDRs       []string `json:"cidrs"`
	Weekdays    []int    `json:"weekdays"`
	StartMinute *int     `json:"start_minute"`
	EndMinute   *int     `json:"end_minute"`
}
type Stage struct {
	Action          string `json:"action"`
	ConnectorID     string `json:"connector_id"`
	AfterSeconds    int    `json:"after_seconds"`
	MinEpisodes     int    `json:"min_episodes"`
	DurationSeconds int    `json:"duration_seconds"`
	RateKbps        int    `json:"rate_kbps"`
	Template        string `json:"template"`
}
type Definition struct {
	ID              string  `json:"policy_id"`
	Name            string  `json:"name"`
	Enabled         bool    `json:"enabled"`
	Priority        int     `json:"priority"`
	Mode            string  `json:"mode"`
	Trigger         string  `json:"trigger"`
	Scope           Scope   `json:"scope"`
	Exempt          Scope   `json:"exempt"`
	Limits          Limits  `json:"limits"`
	SustainSeconds  int     `json:"sustain_seconds"`
	WindowSeconds   int     `json:"window_seconds"`
	RecoverySeconds int     `json:"recovery_seconds"`
	CooldownSeconds int     `json:"cooldown_seconds"`
	Stages          []Stage `json:"stages"`
	Revision        int     `json:"revision"`
}

func (p *Definition) Validate() error {
	if p.ID == "" || p.Name == "" {
		return fmt.Errorf("policy_id and name required")
	}
	if p.Mode == "" {
		p.Mode = "observe"
	}
	if p.Mode != "observe" && p.Mode != "manual" && p.Mode != "automatic" {
		return fmt.Errorf("invalid mode")
	}
	if p.Trigger != "quota_exceeded" && p.Trigger != "shared_access" && p.Trigger != "explicit_proxy" {
		return fmt.Errorf("invalid trigger")
	}
	if p.Trigger == "explicit_proxy" && p.Mode == "automatic" {
		return fmt.Errorf("proxy protocol evidence supports observe or manual mode only")
	}
	if p.Trigger == "shared_access" && p.Mode == "automatic" {
		return fmt.Errorf("shared access supports observe or manual mode until detection and control gates are verified")
	}
	for _, v := range []*int{p.Limits.Total, p.Limits.Mobile, p.Limits.PC} {
		if v != nil && *v < 0 {
			return fmt.Errorf("negative quota")
		}
	}
	if p.WindowSeconds <= 0 {
		p.WindowSeconds = 86400
	}
	if p.SustainSeconds < 0 || p.RecoverySeconds < 0 || p.CooldownSeconds < 0 {
		return fmt.Errorf("negative time interval")
	}
	for _, scope := range []Scope{p.Scope, p.Exempt} {
		for _, cidr := range scope.CIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("invalid CIDR")
			}
		}
		if (scope.StartMinute == nil) != (scope.EndMinute == nil) {
			return fmt.Errorf("both schedule bounds required")
		}
		for _, m := range []*int{scope.StartMinute, scope.EndMinute} {
			if m != nil && (*m < 0 || *m >= 1440) {
				return fmt.Errorf("invalid schedule minute")
			}
		}
		for _, day := range scope.Weekdays {
			if day < 0 || day > 6 {
				return fmt.Errorf("invalid weekday")
			}
		}
	}
	for _, st := range p.Stages {
		if p.Trigger == "shared_access" && st.Action != "disconnect" {
			return fmt.Errorf("shared access currently supports disconnect only; other actions require verified control and recovery capabilities")
		}
		if st.ConnectorID == "" {
			return fmt.Errorf("connector required")
		}
		switch st.Action {
		case "notify":
			if st.Template == "" {
				return fmt.Errorf("notification template required")
			}
		case "rate_limit":
			if st.RateKbps <= 0 || st.DurationSeconds <= 0 {
				return fmt.Errorf("rate and duration required")
			}
		case "disconnect":
		case "disable_account":
			if st.DurationSeconds <= 0 {
				return fmt.Errorf("disable duration required")
			}
		default:
			return fmt.Errorf("unsupported action")
		}
		if st.AfterSeconds < 0 || st.MinEpisodes < 0 {
			return fmt.Errorf("invalid stage timing")
		}
	}
	return nil
}
func contains(values []string, v string) bool {
	if len(values) == 0 {
		return true
	}
	for _, a := range values {
		if a == v {
			return true
		}
	}
	return false
}
func (s Scope) Empty() bool {
	return len(s.Accounts)+len(s.Groups)+len(s.Products)+len(s.Campuses)+len(s.VLANs)+len(s.CIDRs)+len(s.Weekdays) == 0 && s.StartMinute == nil
}
func (s Scope) Match(account string, sessions []Session, now time.Time) bool {
	if !contains(s.Accounts, account) {
		return false
	}
	local := now.In(time.FixedZone("Asia/Shanghai", 8*3600))
	if len(s.Weekdays) > 0 {
		ok := false
		for _, day := range s.Weekdays {
			if day == int(local.Weekday()) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	minute := local.Hour()*60 + local.Minute()
	if s.StartMinute != nil && s.EndMinute != nil {
		a, b := *s.StartMinute, *s.EndMinute
		if a <= b {
			if minute < a || minute >= b {
				return false
			}
		} else if minute < a && minute >= b {
			return false
		}
	}
	for _, session := range sessions {
		if session.AccountID != account || session.State(now) != "active" {
			continue
		}
		if !contains(s.Groups, session.GroupID) || !contains(s.Products, session.ProductID) || !contains(s.Campuses, session.CampusID) || !contains(s.VLANs, session.VLAN) {
			continue
		}
		if len(s.CIDRs) > 0 {
			ip, err := netip.ParseAddr(session.IP)
			if err != nil {
				continue
			}
			found := false
			for _, raw := range s.CIDRs {
				p, _ := netip.ParsePrefix(raw)
				if p.Contains(ip) {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		return true
	}
	return false
}

type Selection struct {
	PolicyID string `json:"policy_id"`
	Matched  bool   `json:"matched"`
	Selected bool   `json:"selected"`
	Reason   string `json:"reason"`
}

func Select(defs []Definition, account string, ss []Session, now time.Time) ([]Definition, []Selection) {
	defs = append([]Definition{}, defs...)
	sort.Slice(defs, func(i, j int) bool {
		if defs[i].Priority != defs[j].Priority {
			return defs[i].Priority > defs[j].Priority
		}
		return defs[i].ID < defs[j].ID
	})
	used := map[string]bool{}
	chosen := []Definition{}
	explain := []Selection{}
	for _, p := range defs {
		item := Selection{PolicyID: p.ID}
		switch {
		case !p.Enabled:
			item.Reason = "disabled"
		case !p.Scope.Match(account, ss, now):
			item.Reason = "scope_or_schedule_mismatch"
		case !p.Exempt.Empty() && p.Exempt.Match(account, ss, now):
			item.Reason = "exempt"
		case used[p.Trigger]:
			item.Matched = true
			item.Reason = "higher_priority_policy_selected"
		default:
			item.Matched = true
			item.Selected = true
			item.Reason = "selected"
			used[p.Trigger] = true
			chosen = append(chosen, p)
		}
		explain = append(explain, item)
	}
	return chosen, explain
}

type Input struct {
	AccountID   string   `json:"account_id"`
	Known       bool     `json:"known"`
	Violated    bool     `json:"violated"`
	Reasons     []string `json:"reasons"`
	EvidenceIDs []string `json:"evidence_ids"`
}
type StageState struct {
	ApprovedSessionBindings []string  `json:"approved_session_bindings,omitempty"`
	ApprovedEvidenceIDs     []string  `json:"approved_evidence_ids,omitempty"`
	CompletedPausedSeconds  int64     `json:"completed_paused_seconds"`
	Index                   int       `json:"index"`
	Key                     string    `json:"idempotency_key"`
	Status                  string    `json:"status"`
	ActionIDs               []string  `json:"action_ids"`
	CompletedAt             time.Time `json:"completed_at"`
}
type Execution struct {
	PausedSince   time.Time    `json:"paused_since"`
	PausedSeconds int64        `json:"paused_seconds"`
	ID            string       `json:"execution_id"`
	PolicyID      string       `json:"policy_id"`
	AccountID     string       `json:"account_id"`
	State         string       `json:"state"`
	Episode       int          `json:"episode"`
	Episodes      []time.Time  `json:"episodes"`
	PendingAt     time.Time    `json:"pending_at"`
	StartedAt     time.Time    `json:"started_at"`
	ClearAt       time.Time    `json:"clear_at"`
	CooldownUntil time.Time    `json:"cooldown_until"`
	LastEvaluated time.Time    `json:"last_evaluated"`
	Stages        []StageState `json:"stages"`
	Reasons       []string     `json:"reasons"`
	EvidenceIDs   []string     `json:"evidence_ids"`
	Definition    Definition   `json:"definition"`
}
type Intent struct {
	Key        string `json:"idempotency_key"`
	AccountID  string `json:"account_id"`
	StageIndex int    `json:"stage_index"`
	Stage      Stage  `json:"stage"`
	Mode       string `json:"mode"`
}
type Decision struct {
	Execution Execution `json:"execution"`
	Intent    *Intent   `json:"intent,omitempty"`
}

func StableID(parts ...string) string {
	raw, _ := json.Marshal(parts)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:16])
}
func Advance(p Definition, e Execution, in Input, now time.Time) Decision {
	if e.ID == "" {
		e = Execution{ID: StableID(p.ID, in.AccountID), PolicyID: p.ID, AccountID: in.AccountID, State: "normal", Definition: p, Stages: []StageState{}, Episodes: []time.Time{}}
	}
	if !e.LastEvaluated.IsZero() && !now.After(e.LastEvaluated) {
		return Decision{Execution: e}
	}
	e.LastEvaluated = now
	e.Reasons = in.Reasons
	e.EvidenceIDs = in.EvidenceIDs
	if now.Before(e.CooldownUntil) {
		return Decision{Execution: e}
	}
	if !in.Known {
		if !e.StartedAt.IsZero() && e.PausedSince.IsZero() {
			e.PausedSince = now
		}
		if e.StartedAt.IsZero() {
			e.PendingAt = time.Time{}
		}
		e.State = "waiting_data"
		e.ClearAt = time.Time{}
		return Decision{Execution: e}
	}
	if !e.PausedSince.IsZero() {
		e.PausedSeconds += int64(now.Sub(e.PausedSince) / time.Second)
		e.PausedSince = time.Time{}
	}
	if !in.Violated {
		e.PendingAt = time.Time{}
		if e.StartedAt.IsZero() {
			e.State = "normal"
			return Decision{Execution: e}
		}
		if e.ClearAt.IsZero() {
			e.ClearAt = now
		}
		if now.Sub(e.ClearAt) >= time.Duration(p.RecoverySeconds)*time.Second {
			e.State = "recovered"
			e.StartedAt = time.Time{}
			e.CooldownUntil = now.Add(time.Duration(p.CooldownSeconds) * time.Second)
		}
		return Decision{Execution: e}
	}
	e.ClearAt = time.Time{}
	if e.StartedAt.IsZero() {
		if e.PendingAt.IsZero() {
			e.PendingAt = now
		}
		e.State = "pending"
		if now.Sub(e.PendingAt) < time.Duration(p.SustainSeconds)*time.Second {
			return Decision{Execution: e}
		}
		e.PausedSeconds = 0
		e.Episode++
		e.StartedAt = now
		e.Stages = []StageState{}
		e.Episodes = append(e.Episodes, now)
		e.Definition = p
	}
	p = e.Definition
	e.State = "violating"
	recent := 0
	for _, at := range e.Episodes {
		if now.Sub(at) <= time.Duration(p.WindowSeconds)*time.Second {
			recent++
		}
	}
	for i, stage := range p.Stages {
		if i < len(e.Stages) {
			st := e.Stages[i]
			if st.Status != "succeeded" && st.Status != "shadow_succeeded" {
				e.State = st.Status
				return Decision{Execution: e}
			}
			continue
		}
		base := e.StartedAt
		paused := e.PausedSeconds
		if i > 0 {
			base = e.Stages[i-1].CompletedAt
			paused -= e.Stages[i-1].CompletedPausedSeconds
		}
		if now.Sub(base)-time.Duration(paused)*time.Second < time.Duration(stage.AfterSeconds)*time.Second || recent < stage.MinEpisodes {
			return Decision{Execution: e}
		}
		key := StableID(e.AccountID, p.ID, fmt.Sprint(e.Episode), fmt.Sprint(i))
		status := "pending_action"
		if p.Mode == "manual" {
			status = "awaiting_approval"
		}
		if p.Mode == "observe" {
			status = "shadow_succeeded"
		}
		state := StageState{Index: i, Key: key, Status: status, ActionIDs: []string{}}
		if p.Mode == "observe" {
			state.CompletedAt = now
			state.CompletedPausedSeconds = e.PausedSeconds
		}
		e.Stages = append(e.Stages, state)
		e.State = status
		return Decision{e, &Intent{key, e.AccountID, i, stage, p.Mode}}
	}
	return Decision{Execution: e}
}
func Revoke(e Execution, now time.Time) Execution {
	if e.State == "revoked" {
		return e
	}
	e.State = "revoked"
	e.CooldownUntil = now.Add(time.Duration(e.Definition.CooldownSeconds) * time.Second)
	e.StartedAt = time.Time{}
	e.PendingAt = time.Time{}
	for i := range e.Stages {
		if e.Stages[i].Status != "succeeded" {
			e.Stages[i].Status = "cancelled"
		}
	}
	return e
}
