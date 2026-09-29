package srunapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/legacy4k"
	"sort"
	"strings"
	"time"
)

type PlannedDisconnectSession struct {
	Target    DisconnectTarget `json:"target"`
	Addresses []string         `json:"addresses"`
}

type AccountDisconnectPlan struct {
	Account      string                     `json:"account"`
	CampusID     string                     `json:"campus_id"`
	AccessDomain string                     `json:"access_domain"`
	Sessions     []PlannedDisconnectSession `json:"sessions"`
	Fingerprint  string                     `json:"fingerprint"`
}

// PlanAccountDisconnect covers every current session in ONE registered source
// scope. Multi-source accounts require plans for every authority; callers must
// not present one source plan as proof of global account coverage. A fingerprint
// binds confirmation to membership and identity, not counters or read timestamp.
func PlanAccountDisconnect(in legacy4k.OnlineInventory, account, campus, domain string, now time.Time, age time.Duration) (AccountDisconnectPlan, error) {
	p := AccountDisconnectPlan{Account: account, CampusID: campus, AccessDomain: domain}
	if strings.TrimSpace(account) == "" || campus == "" || domain == "" {
		return p, fmt.Errorf("explicit account and authority scope required")
	}
	if err := checkedRows(in, now, age); err != nil {
		return p, err
	}
	records, _ := in.IdentityRecords()
	addresses := map[string][]string{}
	for _, r := range records {
		if r["account_id"] == account {
			addresses[r["session_id"]] = append(addresses[r["session_id"]], r["ip"])
		}
	}
	for _, row := range in.Rows {
		if row["user_name"] != account {
			continue
		}
		if row["add_time"] == "" {
			return p, fmt.Errorf("login generation required for account disconnect plan")
		}
		target := binding(in, row)
		ips := addresses[target.SessionID]
		sort.Strings(ips)
		p.Sessions = append(p.Sessions, PlannedDisconnectSession{Target: target, Addresses: ips})
	}
	if len(p.Sessions) == 0 {
		return p, fmt.Errorf("no confirmed online sessions for account")
	}
	sort.Slice(p.Sessions, func(i, j int) bool { return p.Sessions[i].Target.SessionID < p.Sessions[j].Target.SessionID })
	body, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	digest := sha256.Sum256(body)
	p.Fingerprint = hex.EncodeToString(digest[:])
	return p, nil
}
