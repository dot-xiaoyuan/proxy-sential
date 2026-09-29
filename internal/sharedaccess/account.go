package sharedaccess

import (
	"proxy-sentinel/internal/policy"
	"sort"
	"time"
)

type Scope struct{ IP, SensorID, CampusID, AccessDomain string }

func windowScope(w Window) Scope { return Scope{w.IP, w.SensorID, w.CampusID, w.AccessDomain} }

// AccountResults chooses the newest observation before looking at its verdict.
// Never fall back to an older positive window when the newest is incomplete,
// negative or attributed to someone else. Expected capture scopes come from
// registration, rather than whichever observations happen to be available.
func AccountResults(account string, windows []Window, cfg Config, sessions []policy.Session, now time.Time, lookback time.Duration) []Result {
	latest := map[Scope]Window{}
	for _, w := range windows {
		if w.To.After(now) || w.To.Before(now.Add(-lookback)) {
			continue
		}
		k := windowScope(w)
		old, ok := latest[k]
		if !ok || w.To.After(old.To) || (w.To.Equal(old.To) && w.ID > old.ID) {
			latest[k] = w
		}
	}
	expected := map[Scope]bool{}
	for _, s := range sessions {
		if s.AccountID != account || s.StartedAt.After(now) || (!s.EndedAt.IsZero() && s.EndedAt.Before(now.Add(-lookback))) {
			continue
		}
		registered := false
		for _, source := range cfg.Sources {
			if source.CampusID == s.CampusID && source.AccessDomain == s.AccessDomain {
				registered = true
				expected[Scope{s.IP, source.SensorID, s.CampusID, s.AccessDomain}] = true
			}
		}
		if !registered {
			expected[Scope{s.IP, "", s.CampusID, s.AccessDomain}] = true
		}
	}
	keys := make([]Scope, 0, len(expected))
	for k := range expected {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.CampusID != b.CampusID {
			return a.CampusID < b.CampusID
		}
		if a.AccessDomain != b.AccessDomain {
			return a.AccessDomain < b.AccessDomain
		}
		if a.SensorID != b.SensorID {
			return a.SensorID < b.SensorID
		}
		return a.IP < b.IP
	})
	out := make([]Result, 0, len(keys))
	for _, k := range keys {
		w, ok := latest[k]
		if !ok {
			out = append(out, Result{State: "insufficient", AccountID: account, IP: k.IP, SensorID: k.SensorID, CampusID: k.CampusID, AccessDomain: k.AccessDomain, Reasons: []string{"missing_shared_scope_observation"}})
			continue
		}
		result := Evaluate(w, cfg, sessions, now, lookback)
		if result.AccountID != "" && result.AccountID != account {
			result = Result{State: "insufficient", AccountID: account, IP: k.IP, SensorID: k.SensorID, CampusID: k.CampusID, AccessDomain: k.AccessDomain, Reasons: []string{"shared_scope_account_changed"}}
		}
		out = append(out, result)
	}
	return out
}
