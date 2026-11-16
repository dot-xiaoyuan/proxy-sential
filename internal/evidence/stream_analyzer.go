package evidence

import (
	"errors"
	"sort"
	"time"

	"proxy-sentinel/internal/normalized"
)

// FixedWindowStreamAnalyzer reduces a verified event stream directly into
// signal sets. The fixed AsOf is essential: without it a later event could
// move the window after an earlier event has already been reduced.
type FixedWindowStreamAnalyzer struct {
	window    time.Duration
	cutoff    time.Time
	stats     Stats
	maxTime   time.Time
	seen      map[string]struct{}
	byIP      map[string]ipSignals
	byAccount map[string]accountSignals
}

func NewFixedWindowStreamAnalyzer(opts Options) (*FixedWindowStreamAnalyzer, error) {
	if opts.AsOf.IsZero() {
		return nil, errors.New("streaming risk analysis requires a fixed as-of time")
	}
	window := opts.Window
	if window == 0 {
		window = 10 * time.Minute
	}
	if window <= 0 {
		return nil, errors.New("streaming risk analysis requires a positive window")
	}
	return &FixedWindowStreamAnalyzer{
		window: window, cutoff: opts.AsOf.UTC().Add(-window), seen: map[string]struct{}{},
		byIP: map[string]ipSignals{}, byAccount: map[string]accountSignals{},
	}, nil
}

func (a *FixedWindowStreamAnalyzer) Add(event normalized.Event) error {
	if a == nil {
		return errors.New("risk stream analyzer is nil")
	}
	a.stats.Read++
	if event.Type == "discovery" || event.EventID == "" || event.Timestamp == "" || event.Subject == nil {
		a.stats.Skipped++
		return nil
	}
	if _, duplicate := a.seen[event.EventID]; duplicate {
		a.stats.Duplicate++
		return nil
	}
	a.seen[event.EventID] = struct{}{}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		a.stats.Skipped++
		return nil
	}
	ip, ok := event.Subject["ip"].(string)
	if !ok || ip == "" {
		a.stats.Skipped++
		return nil
	}
	a.stats.Accepted++
	if at.After(a.maxTime) {
		a.maxTime = at
	}
	// An empty signal set still records the subject so that Result has exactly
	// the same expiry behavior as Analyze's fixed-window replay.
	signals, found := a.byIP[ip]
	if !found {
		signals = newIPSignals()
	}
	if !at.Before(a.cutoff) {
		signals.add(event, at)
	}
	a.byIP[ip] = signals
	if accountID := subjectString(event, "account_id"); accountID != "" {
		account, found := a.byAccount[accountID]
		if !found {
			account = newAccountSignals()
		}
		if !at.Before(a.cutoff) {
			account.add(event, at)
		}
		a.byAccount[accountID] = account
	}
	return nil
}

func (a *FixedWindowStreamAnalyzer) Result() Result {
	result := Result{Stats: a.stats, Evidence: []Evidence{}}
	if !a.maxTime.IsZero() {
		result.MaxTime = a.maxTime.Format(time.RFC3339Nano)
	}
	ips := make([]string, 0, len(a.byIP))
	for ip := range a.byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		result.Evidence = append(result.Evidence, buildEvidence(ip, a.window, a.maxTime, a.byIP[ip])...)
	}
	accounts := make([]string, 0, len(a.byAccount))
	for account := range a.byAccount {
		accounts = append(accounts, account)
	}
	sort.Strings(accounts)
	for _, account := range accounts {
		result.Evidence = append(result.Evidence, buildAccountEvidence(account, a.window, a.maxTime, a.byAccount[account])...)
	}
	return result
}
