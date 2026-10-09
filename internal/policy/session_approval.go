package policy

import (
	"fmt"
	"sort"
	"time"
)

// SessionApprovalBindings captures attachment identity, excluding heartbeats
// and accounting counters. Each IP binding is retained; it is not a device count.
func SessionApprovalBindings(account string, sessions []Session, now time.Time) ([]string, error) {
	if account == "" {
		return nil, fmt.Errorf("account required")
	}
	bindings := map[string]bool{}
	for _, s := range sessions {
		if s.AccountID != account || s.State(now) == "ended" || s.State(now) == "absent" {
			continue
		}
		attr := AttributeForSession(sessions, s, now)
		if s.State(now) != "active" || attr.State != "resolved" || attr.AccountID != account || s.ID == "" {
			return nil, fmt.Errorf("account session identity uncertain")
		}
		bindings[StableID(account, s.Source, s.SensorID, s.CampusID, s.AccessDomain, s.ID, s.StartedAt.UTC().Format(time.RFC3339Nano), s.IP, s.MAC, s.EndpointID)] = true
	}
	out := make([]string, 0, len(bindings))
	for b := range bindings {
		out = append(out, b)
	}
	sort.Strings(out)
	return out, nil
}

// Disappeared approved sessions need no replacement. New or rebound sessions
// require a fresh approval and may not inherit an earlier disconnect intent.
func ValidateSessionApproval(account string, approved []string, sessions []Session, now time.Time) error {
	if len(approved) == 0 {
		return fmt.Errorf("manual session approval required")
	}
	current, err := SessionApprovalBindings(account, sessions, now)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, b := range approved {
		allowed[b] = true
	}
	for _, b := range current {
		if !allowed[b] {
			return fmt.Errorf("account sessions changed; renewed approval required")
		}
	}
	return nil
}
