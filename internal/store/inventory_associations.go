package store

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type inventoryLatestAssociations struct {
	Account           string
	AccountCandidates []string
	AccountAt         time.Time
	AccountConflict   bool
	Access            string
	AccessAt          time.Time
	AccessConflict    bool
	IP                string
	IPAt              time.Time
}

type latestAssociationValues struct {
	at     time.Time
	values map[string]bool
}

func (v *latestAssociationValues) observe(value, timestamp string, now time.Time) {
	if strings.TrimSpace(value) == "" {
		return
	}
	at, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || at.IsZero() || at.After(now) {
		return
	}
	if at.After(v.at) {
		v.at = at
		v.values = map[string]bool{value: true}
	} else if at.Equal(v.at) {
		v.values[value] = true
	}
}
func (v latestAssociationValues) sorted() []string {
	values := []string{}
	for value := range v.values {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
func associationSessionTime(s AccountSession, now time.Time) string {
	// Processing-time updated_at is deliberately not a candidate.
	result := ""
	var latest time.Time
	for _, stamp := range []string{s.StartedAt, s.LastConfirmedAt, s.EndedAt} {
		at, err := time.Parse(time.RFC3339Nano, stamp)
		if err == nil && !at.IsZero() && !at.After(now) && at.After(latest) {
			latest = at
			result = at.UTC().Format(time.RFC3339Nano)
		}
	}
	return result
}
func latestInventoryAssociations(profile EndpointIdentityProfile, now time.Time) inventoryLatestAssociations {
	accounts, access, ips := latestAssociationValues{}, latestAssociationValues{}, latestAssociationValues{}
	for _, s := range profile.Sessions {
		at := associationSessionTime(s, now)
		accounts.observe(s.AccountID, at, now)
		access.observe(s.AccessID, at, now)
		if ip := net.ParseIP(s.IP); ip != nil && !ip.IsUnspecified() {
			ips.observe(ip.String(), at, now)
		}
	}
	for _, h := range profile.IPHistory {
		accounts.observe(h.AccountID, h.LastSeen, now)
		if ip := net.ParseIP(h.IP); ip != nil && !ip.IsUnspecified() {
			ips.observe(ip.String(), h.LastSeen, now)
		}
	}
	for _, h := range profile.AccessHistory {
		accounts.observe(h.AccountID, h.LastSeen, now)
		access.observe(h.AccessID, h.LastSeen, now)
	}
	result := inventoryLatestAssociations{AccountCandidates: accounts.sorted(), AccountAt: accounts.at, AccessAt: access.at, IPAt: ips.at}
	if len(result.AccountCandidates) == 1 {
		result.Account = result.AccountCandidates[0]
	} else {
		result.AccountConflict = len(result.AccountCandidates) > 1
	}
	values := access.sorted()
	if len(values) == 1 {
		result.Access = values[0]
	} else {
		result.AccessConflict = len(values) > 1
	}
	values = ips.sorted()
	eligible := []IdentityIPMACHistory{}
	for _, h := range profile.IPHistory {
		stamp, err := time.Parse(time.RFC3339Nano, h.LastSeen)
		if err == nil && !stamp.After(now) && net.ParseIP(h.IP) != nil {
			eligible = append(eligible, h)
		}
	}
	preferred := recentEndpointIP(eligible)
	if ip := net.ParseIP(preferred); ip != nil {
		preferred = ip.String()
	}
	sort.SliceStable(values, func(i, j int) bool {
		if (values[i] == preferred) != (values[j] == preferred) {
			return values[i] == preferred
		}
		a, b := net.ParseIP(values[i]), net.ParseIP(values[j])
		if (a.To4() != nil) != (b.To4() != nil) {
			return a.To4() != nil
		}
		return values[i] < values[j]
	})
	if len(values) > 0 {
		result.IP = values[0]
	}
	return result
}
func applyLatestInventoryAssociations(item *EndpointDeviceInventory, profile EndpointIdentityProfile, now time.Time) {
	latest := latestInventoryAssociations(profile, now)
	item.CurrentAccount = latest.Account
	item.CurrentAccountCandidates = latest.AccountCandidates
	item.CurrentAccountConflict = latest.AccountConflict
	item.CurrentAccountObservedAt = ""
	if !latest.AccountAt.IsZero() {
		item.CurrentAccountObservedAt = latest.AccountAt.UTC().Format(time.RFC3339Nano)
	}
	item.CurrentAccessID = latest.Access
	item.CurrentAccessConflict = latest.AccessConflict
	item.CurrentIP = latest.IP
}

func NormalizeInventorySearch(q *Query) error { return normalizeInventorySearch(q) }
func normalizeInventorySearch(q *Query) error {
	q.Q = strings.TrimSpace(q.Q)
	if q.SrcIP != "" {
		ip := net.ParseIP(strings.TrimSpace(q.SrcIP))
		if ip == nil {
			return fmt.Errorf("invalid IP filter")
		}
		q.SrcIP = ip.String()
	}
	if q.InventorySearchType == "" {
		q.InventorySearchType = "all"
	}
	switch q.InventorySearchType {
	case "all", "account", "name", "ip", "mac":
	default:
		return fmt.Errorf("invalid search_type")
	}
	if len(q.Q) > 256 {
		return fmt.Errorf("search value exceeds 256 bytes")
	}
	if q.Q == "" {
		return nil
	}
	if q.InventorySearchType == "all" || q.InventorySearchType == "name" {
		q.Q = strings.ToLower(q.Q)
		if q.InventorySearchType == "all" {
			if ip := net.ParseIP(q.Q); ip != nil {
				q.Q = ip.String()
			}
		}
	}
	if q.InventorySearchType == "ip" {
		ip := net.ParseIP(q.Q)
		if ip == nil {
			return fmt.Errorf("invalid IP search value")
		}
		q.Q = ip.String()
	}
	if q.InventorySearchType == "mac" {
		if len(q.Q) != 12 {
			mac, err := net.ParseMAC(q.Q)
			if err != nil || len(mac) != 6 {
				return fmt.Errorf("invalid MAC search value")
			}
		}
		key := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(q.Q))
		if len(key) != 12 {
			return fmt.Errorf("invalid MAC search value")
		}
		for _, c := range key {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return fmt.Errorf("invalid MAC search value")
			}
		}
		q.Q = key
	}
	return nil
}
