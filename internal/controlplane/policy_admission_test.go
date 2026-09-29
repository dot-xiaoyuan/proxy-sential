package controlplane

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestQueuedQuotaActionRechecksCurrentPolicy(t *testing.T) {
	now := time.Now().UTC()
	original := policy.Definition{ID: "quota", Enabled: true, Mode: "automatic", Trigger: "quota_exceeded", Revision: 1, Priority: 1}
	ex := policy.Execution{PolicyID: "quota", AccountID: "a", Definition: original}
	ss := []policy.Session{{ID: "s", AccountID: "a", Source: "auth", CampusID: "c", AccessDomain: "nas", IP: "192.0.2.1", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}}
	for _, name := range []string{"unchanged", "disabled", "observe", "revised", "exempt", "replaced", "removed"} {
		t.Run(name, func(t *testing.T) {
			current := original
			defs := []policy.Definition{}
			switch name {
			case "disabled":
				current.Enabled = false
			case "observe":
				current.Mode = "observe"
			case "revised":
				current.Revision++
			case "exempt":
				current.Exempt.Accounts = []string{"a"}
			case "replaced":
				higher := original
				higher.ID = "higher"
				higher.Priority = 9
				defs = append(defs, higher)
			}
			if name != "removed" {
				defs = append(defs, current)
			}
			err := validateCurrentPolicySelection(ex, defs, ss, now)
			if (err == nil) != (name == "unchanged") {
				t.Fatalf("unexpected admission: %v", err)
			}
		})
	}
}
