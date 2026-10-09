package policy

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Whitelist exempts actions, never collection, evidence or risk scoring.
type WhitelistEntry struct {
	ID           string     `json:"entry_id"`
	Type         string     `json:"type"`
	Value        string     `json:"value"`
	Reason       string     `json:"reason"`
	CampusID     string     `json:"campus_id,omitempty"`
	AccessDomain string     `json:"access_domain,omitempty"`
	Enabled      bool       `json:"enabled"`
	ValidFrom    time.Time  `json:"valid_from"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Revision     int        `json:"revision"`
	CreatedBy    string     `json:"created_by"`
	UpdatedBy    string     `json:"updated_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type WhitelistSubject struct{ AccountID, IP, MAC, GroupID, CampusID, AccessDomain string }

func whitelistIP(raw string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("IP 地址格式不正确")
	}
	return a.Unmap(), nil
}

func NormalizeWhitelist(e *WhitelistEntry) error {
	e.Type = strings.TrimSpace(e.Type)
	e.Value = strings.TrimSpace(e.Value)
	e.Reason = strings.TrimSpace(e.Reason)
	e.CampusID = strings.TrimSpace(e.CampusID)
	e.AccessDomain = strings.TrimSpace(e.AccessDomain)
	if e.Value == "" || len(e.Value) > 256 || len([]rune(e.Reason)) < 2 || len(e.Reason) > 2000 || len(e.CampusID) > 128 || len(e.AccessDomain) > 128 {
		return fmt.Errorf("请填写有效的匹配值和至少两个字的原因")
	}
	if e.AccessDomain != "" && e.CampusID == "" {
		return fmt.Errorf("限定接入域时必须同时指定校区")
	}
	switch e.Type {
	case "ip":
		a, err := whitelistIP(e.Value)
		if err != nil {
			return err
		}
		e.Value = a.String()
	case "mac":
		m, err := net.ParseMAC(e.Value)
		if err != nil || len(m) != 6 {
			return fmt.Errorf("请输入完整的 48 位 MAC 地址")
		}
		e.Value = strings.ToLower(m.String())
	case "network":
		if strings.Contains(e.Value, "/") {
			p, err := netip.ParsePrefix(e.Value)
			if err != nil || p.Addr().Zone() != "" {
				return fmt.Errorf("网段格式不正确")
			}
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return fmt.Errorf("不支持该映射网段")
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			e.Value = p.Masked().String()
		} else if strings.Contains(e.Value, "-") {
			parts := strings.Split(e.Value, "-")
			if len(parts) != 2 {
				return fmt.Errorf("请输入起始 IP-结束 IP")
			}
			a, err := whitelistIP(parts[0])
			b, other := whitelistIP(parts[1])
			if err != nil || other != nil || a.BitLen() != b.BitLen() || a.Compare(b) > 0 {
				return fmt.Errorf("地址范围必须同属 IPv4 或 IPv6，且起始地址不能大于结束地址")
			}
			e.Value = a.String() + "-" + b.String()
		} else {
			a, err := whitelistIP(e.Value)
			if err != nil {
				return err
			}
			e.Value = a.String()
		}
	case "account", "group":
		if strings.ContainsAny(e.Value, "\r\n\x00") {
			return fmt.Errorf("账号或用户组标识格式不正确")
		}
	default:
		return fmt.Errorf("白名单类型不正确")
	}
	if e.ValidFrom.IsZero() || e.ExpiresAt != nil && !e.ExpiresAt.After(e.ValidFrom) {
		return fmt.Errorf("失效时间必须晚于生效时间")
	}
	return nil
}

func (e WhitelistEntry) Active(now time.Time) bool {
	return e.Enabled && !e.ValidFrom.IsZero() && !now.Before(e.ValidFrom) && (e.ExpiresAt == nil || now.Before(*e.ExpiresAt))
}

func MatchWhitelist(entries []WhitelistEntry, subject WhitelistSubject, now time.Time) *WhitelistEntry {
	for _, kind := range []string{"ip", "account", "mac", "network", "group"} {
		for _, e := range entries {
			if e.Type != kind || !e.Active(now) || e.CampusID != "" && e.CampusID != subject.CampusID || e.AccessDomain != "" && e.AccessDomain != subject.AccessDomain {
				continue
			}
			matched := false
			switch kind {
			case "account":
				matched = subject.AccountID != "" && e.Value == subject.AccountID
			case "group":
				matched = subject.GroupID != "" && e.Value == subject.GroupID
			case "mac":
				m, err := net.ParseMAC(subject.MAC)
				matched = err == nil && len(m) == 6 && e.Value == strings.ToLower(m.String())
			case "ip", "network":
				a, err := whitelistIP(subject.IP)
				if err != nil {
					continue
				}
				if p, err := netip.ParsePrefix(e.Value); err == nil {
					matched = p.Contains(a)
				} else if parts := strings.Split(e.Value, "-"); len(parts) == 2 {
					start, err := whitelistIP(parts[0])
					end, other := whitelistIP(parts[1])
					matched = err == nil && other == nil && a.BitLen() == start.BitLen() && a.Compare(start) >= 0 && a.Compare(end) <= 0
				} else {
					ip, err := whitelistIP(e.Value)
					matched = err == nil && ip == a
				}
			}
			if matched {
				return &e
			}
		}
	}
	return nil
}

func MatchAccountWhitelist(entries []WhitelistEntry, account string, sessions []Session, now time.Time) *WhitelistEntry {
	if m := MatchWhitelist(entries, WhitelistSubject{AccountID: account}, now); m != nil {
		return m
	}
	for _, s := range sessions {
		if s.AccountID == account && s.State(now) == "active" {
			if m := MatchWhitelist(entries, WhitelistSubject{AccountID: account, IP: s.IP, MAC: s.MAC, GroupID: s.GroupID, CampusID: s.CampusID, AccessDomain: s.AccessDomain}, now); m != nil {
				return m
			}
		}
	}
	return nil
}

func SuppressWhitelist(p Definition, e Execution, in Input, match WhitelistEntry, now time.Time) Execution {
	if e.ID == "" {
		e = Execution{ID: StableID(p.ID, in.AccountID), PolicyID: p.ID, AccountID: in.AccountID, Definition: p, Stages: []StageState{}, Episodes: []time.Time{}}
	}
	if e.State != "whitelist_suppressed" {
		e = Revoke(e, now)
	}
	e.State = "whitelist_suppressed"
	e.LastEvaluated = now
	e.Reasons = []string{"whitelist_suppressed", "whitelist_entry:" + match.ID}
	e.EvidenceIDs = append([]string{}, in.EvidenceIDs...)
	for i := range e.Stages {
		e.Stages[i].ApprovedSessionBindings = nil
		e.Stages[i].ApprovedEvidenceIDs = nil
	}
	return e
}
