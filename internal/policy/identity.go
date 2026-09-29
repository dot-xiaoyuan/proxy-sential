// Package policy implements account business policy independently of packet parsing and risk scoring.
package policy

import (
	"net"
	"sort"
	"strings"
	"time"
)

type IdentityCoverage struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type Session struct {
	IdentityIssue    string             `json:"identity_issue,omitempty"`
	SensorID         string             `json:"sensor_id,omitempty"`
	SourceCoverage   []IdentityCoverage `json:"source_coverage,omitempty"`
	Status           string             `json:"session_status,omitempty"`
	Confirmations    []time.Time        `json:"confirmations,omitempty"`
	ID               string             `json:"session_id"`
	AccountID        string             `json:"account_id"`
	EndpointID       string             `json:"endpoint_id"`
	IP               string             `json:"ip"`
	MAC              string             `json:"mac"`
	CampusID         string             `json:"campus_id"`
	AccessDomain     string             `json:"access_domain"`
	GroupID          string             `json:"group_id"`
	ProductID        string             `json:"product_id"`
	VLAN             string             `json:"vlan"`
	Source           string             `json:"source"`
	StartedAt        time.Time          `json:"started_at"`
	EndedAt          time.Time          `json:"ended_at"`
	ConfirmedAt      time.Time          `json:"last_confirmed_at"`
	HeartbeatSeconds int                `json:"heartbeat_interval_seconds"`
	ReconcileSeconds int                `json:"reconcile_interval_seconds"`
	DeviceClass      string             `json:"device_class"`
	BindingConflict  bool               `json:"binding_conflict"`
}

func (s Session) State(at time.Time) string {
	if s.StartedAt.IsZero() || at.Before(s.StartedAt) {
		return "absent"
	}
	if !s.EndedAt.IsZero() && !at.Before(s.EndedAt) {
		return "ended"
	}
	if s.IdentityIssue != "" {
		return "unknown"
	}
	// Evaluate source outages at the requested event time, never at query time.
	if len(s.SourceCoverage) > 0 && !at.Before(s.SourceCoverage[0].From) {
		covered := false
		for _, window := range s.SourceCoverage {
			if !at.Before(window.From) && at.Before(window.To) {
				covered = true
				break
			}
		}
		if !covered {
			return "unknown"
		}
	}
	period := s.HeartbeatSeconds
	if period <= 0 {
		period = s.ReconcileSeconds
	}
	if s.BindingConflict || s.AccountID == "" || s.Source == "" || period <= 0 || s.ConfirmedAt.IsZero() || !at.Before(s.ConfirmedAt.Add(time.Duration(3*period)*time.Second)) {
		return "unknown"
	}
	if len(s.Confirmations) == 0 && at.Before(s.ConfirmedAt) {
		return "unknown"
	}
	if len(s.Confirmations) > 0 {
		covered := false
		for _, confirmed := range s.Confirmations {
			if !at.Before(confirmed) && at.Before(confirmed.Add(time.Duration(3*period)*time.Second)) {
				covered = true
				break
			}
		}
		if !covered {
			return "unknown"
		}
	}
	return "active"
}

type Attribution struct {
	State      string   `json:"state"`
	AccountID  string   `json:"account_id,omitempty"`
	SessionIDs []string `json:"session_ids"`
	Reasons    []string `json:"reasons"`
}

func Attribute(ss []Session, campus, domain, ip string, at time.Time) Attribution {
	a := Attribution{State: "unknown", SessionIDs: []string{}, Reasons: []string{}}
	accounts := map[string]bool{}
	unknown := false
	if campus == "" || domain == "" {
		a.Reasons = append(a.Reasons, "missing_access_scope")
		return a
	}
	for _, s := range ss {
		if s.CampusID != campus || s.AccessDomain != domain || s.IP != ip {
			continue
		}
		state := s.State(at)
		if state == "unknown" {
			unknown = true
		}
		if state == "active" {
			accounts[s.AccountID] = true
			a.SessionIDs = append(a.SessionIDs, s.ID)
		}
	}
	sort.Strings(a.SessionIDs)
	if len(accounts) > 1 {
		a.State = "conflict"
		a.Reasons = append(a.Reasons, "multiple_accounts_at_event_time")
	} else if len(accounts) == 1 && !unknown {
		a.State = "resolved"
		for account := range accounts {
			a.AccountID = account
		}
	} else {
		a.Reasons = append(a.Reasons, "missing_or_stale_identity")
	}
	return a
}

type Limits struct {
	Total  *int `json:"total"`
	Mobile *int `json:"mobile"`
	PC     *int `json:"pc"`
}
type Device struct {
	ID         string   `json:"id"`
	Class      string   `json:"class"`
	SessionIDs []string `json:"session_ids"`
}
type Quota struct {
	AccountID         string   `json:"account_id"`
	State             string   `json:"state"`
	Total             int      `json:"total"`
	Mobile            int      `json:"mobile"`
	PC                int      `json:"pc"`
	Other             int      `json:"other"`
	UncertainSessions int      `json:"uncertain_sessions"`
	CoverageComplete  bool     `json:"coverage_complete"`
	Devices           []Device `json:"devices"`
	Reasons           []string `json:"reasons"`
	Limits            Limits   `json:"limits"`
}

func EvaluateQuota(account string, ss []Session, limits Limits, at time.Time) Quota {
	q := Quota{AccountID: account, State: "compliant", CoverageComplete: true, Devices: []Device{}, Reasons: []string{}, Limits: limits}
	devices := map[string]*Device{}
	present := false
	type accessKey struct{ campus, domain, ip string }
	grouped := map[accessKey][]Session{}
	for _, session := range ss {
		k := accessKey{session.CampusID, session.AccessDomain, session.IP}
		grouped[k] = append(grouped[k], session)
	}
	attributed := map[accessKey]Attribution{}
	for _, s := range ss {
		if s.AccountID != account {
			continue
		}
		state := s.State(at)
		if state == "absent" || state == "ended" {
			continue
		}
		present = true
		if state != "active" {
			q.UncertainSessions++
			q.CoverageComplete = false
			continue
		}
		k := accessKey{s.CampusID, s.AccessDomain, s.IP}
		a, ok := attributed[k]
		if !ok {
			a = Attribute(grouped[k], s.CampusID, s.AccessDomain, s.IP, at)
			attributed[k] = a
		}
		if a.State != "resolved" || a.AccountID != account {
			q.UncertainSessions++
			q.CoverageComplete = false
			continue
		}
		key := ""
		if s.EndpointID != "" && !strings.HasPrefix(s.EndpointID, "mac:") {
			key = "endpoint:" + s.EndpointID
		} else if mac, err := net.ParseMAC(s.MAC); err == nil && len(mac) == 6 && mac[0]&3 == 0 {
			key = "mac:" + strings.ToLower(mac.String())
		}
		if key == "" {
			q.UncertainSessions++
			q.CoverageComplete = false
			continue
		}
		class := s.DeviceClass
		if class != "mobile" && class != "pc" {
			class = "other"
		}
		d := devices[key]
		if d == nil {
			d = &Device{ID: key, Class: class, SessionIDs: []string{}}
			devices[key] = d
		}
		if d.Class != class {
			d.Class = "other"
		}
		d.SessionIDs = append(d.SessionIDs, s.ID)
	}
	if !present {
		q.CoverageComplete = false
		q.Reasons = append(q.Reasons, "no_fresh_online_inventory")
	}
	for _, d := range devices {
		q.Total++
		switch d.Class {
		case "mobile":
			q.Mobile++
		case "pc":
			q.PC++
		default:
			q.Other++
		}
		sort.Strings(d.SessionIDs)
		q.Devices = append(q.Devices, *d)
	}
	sort.Slice(q.Devices, func(i, j int) bool { return q.Devices[i].ID < q.Devices[j].ID })
	if !q.CoverageComplete {
		q.State = "unknown"
		q.Reasons = append(q.Reasons, "identity_or_device_coverage_incomplete")
	}
	if limits.Total != nil && q.Total > *limits.Total {
		q.Reasons = append(q.Reasons, "total_exceeded")
		q.State = "exceeded"
	}
	if limits.Mobile != nil && q.Mobile > *limits.Mobile {
		q.Reasons = append(q.Reasons, "mobile_exceeded")
		q.State = "exceeded"
	}
	if limits.PC != nil && q.PC > *limits.PC {
		q.Reasons = append(q.Reasons, "pc_exceeded")
		q.State = "exceeded"
	}
	return q
}
