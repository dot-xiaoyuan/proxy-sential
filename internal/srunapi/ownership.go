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

// DisconnectTarget is immutable confirmation material, not a completion receipt.
// Persist it with action intent before sending any native operation.
type DisconnectTarget struct {
	Account     string `json:"account"`
	InstanceID  string `json:"instance_id"`
	SessionID   string `json:"session_id"`
	RawOnlineID string `json:"raw_online_id"`
	BindingHash string `json:"binding_hash"`
}

// checkedRows accepts only a complete inventory returned successfully by the
// authoritative ReadOnlineInventory reader. A failed/partial read must not be
// converted to an empty inventory by callers.
func checkedRows(in legacy4k.OnlineInventory, now time.Time, age time.Duration) error {
	if age <= 0 || age > time.Minute || in.ObservedAt.After(now) || now.Sub(in.ObservedAt) > age {
		return fmt.Errorf("online inventory freshness invalid")
	}
	if _, err := in.IdentityRecords(); err != nil {
		return fmt.Errorf("invalid complete online inventory")
	}
	seen := map[string]bool{}
	for _, row := range in.Rows {
		id := row["rad_online_id"]
		if id == "" || strings.TrimSpace(id) != id || seen[id] {
			return fmt.Errorf("missing or duplicate native online ID")
		}
		seen[id] = true
	}
	return nil
}

func binding(in legacy4k.OnlineInventory, row map[string]string) DisconnectTarget {
	sid := row["session_id"]
	if sid == "" {
		sid = row["rad_online_id"]
	}
	// Counters/heartbeat updates are deliberately excluded; identity, attachment
	// and login generation changes require a new confirmation.
	values := []string{in.InstanceID, sid, row["rad_online_id"], row["user_name"], row["ip"], row["ipv6"], row["ip6"], row["add_time"], row["nas_ip"], row["user_mac"], row["device_id"]}
	b, _ := json.Marshal(values)
	h := sha256.Sum256(b)
	return DisconnectTarget{Account: row["user_name"], InstanceID: in.InstanceID, SessionID: legacy4k.OnlineSessionID(in.InstanceID, sid, row["add_time"]), RawOnlineID: row["rad_online_id"], BindingHash: hex.EncodeToString(h[:])}
}

// BindDisconnect resolves the confirmed Sentinel session to a native online ID.
// It never splits composite IDs heuristically or falls back to IP targeting.
func BindDisconnect(in legacy4k.OnlineInventory, account, session string, now time.Time, age time.Duration) (DisconnectTarget, error) {
	if account == "" || session == "" {
		return DisconnectTarget{}, fmt.Errorf("explicit confirmed account and session required")
	}
	if err := checkedRows(in, now, age); err != nil {
		return DisconnectTarget{}, err
	}
	for _, row := range in.Rows {
		t := binding(in, row)
		if t.SessionID == session && t.Account == account {
			if row["add_time"] == "" {
				return DisconnectTarget{}, fmt.Errorf("login generation required for native disconnect")
			}
			return t, nil
		}
	}
	return DisconnectTarget{}, fmt.Errorf("confirmed session is no longer uniquely owned")
}

// CheckDisconnect returns online, absent, changed or unknown. Only a fresh
// complete read after the operation boundary can prove absence. Absence does
// not prove causation, nor that other/new account sessions have been removed.
func CheckDisconnect(target DisconnectTarget, in legacy4k.OnlineInventory, since, now time.Time, age time.Duration) string {
	if target.Account == "" || target.SessionID == "" || target.RawOnlineID == "" || target.BindingHash == "" || since.IsZero() || checkedRows(in, now, age) != nil || in.InstanceID != target.InstanceID || in.ObservedAt.Before(since) {
		return "unknown"
	}
	for _, row := range in.Rows {
		current := binding(in, row)
		if row["rad_online_id"] != target.RawOnlineID && current.SessionID != target.SessionID {
			continue
		}
		if current != target {
			return "changed"
		}
		return "online"
	}
	return "absent"
}

type AccountDisconnectObservation struct {
	State       string            `json:"state"`
	Sessions    map[string]string `json:"sessions"`
	NewSessions []string          `json:"new_sessions"`
}

// CheckAccountDisconnect summarizes a persisted nonempty set of confirmed
// session targets. New logins remain visible and require a fresh confirmation;
// a one-off disconnect does not imply login prevention. A completed observation
// is not by itself a controller action receipt (durable intent is also required).
func CheckAccountDisconnect(targets []DisconnectTarget, in legacy4k.OnlineInventory, since, now time.Time, age time.Duration) AccountDisconnectObservation {
	r := AccountDisconnectObservation{State: "unknown", Sessions: map[string]string{}, NewSessions: []string{}}
	if len(targets) == 0 || checkedRows(in, now, age) != nil {
		return r
	}
	account := targets[0].Account
	known := map[string]bool{}
	absent, online := 0, 0
	uncertain := false
	for _, t := range targets {
		if t.Account != account || known[t.SessionID] {
			return AccountDisconnectObservation{State: "unknown", Sessions: map[string]string{}, NewSessions: []string{}}
		}
		known[t.SessionID] = true
		state := CheckDisconnect(t, in, since, now, age)
		r.Sessions[t.SessionID] = state
		switch state {
		case "absent":
			absent++
		case "online":
			online++
		default:
			uncertain = true
		}
	}
	if uncertain {
		return r
	}
	for _, row := range in.Rows {
		t := binding(in, row)
		if t.Account == account && !known[t.SessionID] {
			r.NewSessions = append(r.NewSessions, t.SessionID)
		}
	}
	sort.Strings(r.NewSessions)
	switch {
	case absent == len(targets) && len(r.NewSessions) == 0:
		r.State = "completed"
	case absent > 0:
		r.State = "partial"
	case online == len(targets):
		r.State = "pending"
	}
	return r
}
