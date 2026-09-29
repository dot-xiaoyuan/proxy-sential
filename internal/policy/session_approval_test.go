package policy

import (
	"testing"
	"time"
)

func TestDisconnectSessionApprovalTracksIdentityNotHeartbeat(t *testing.T) {
	now := time.Now().UTC()
	base := Session{ID: "s1", AccountID: "a", Source: "auth", SensorID: "sensor", CampusID: "c", AccessDomain: "nas", IP: "192.0.2.1", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}
	approved, err := SessionApprovalBindings("a", []Session{base}, now)
	if err != nil || len(approved) != 1 {
		t.Fatal(err)
	}
	for _, name := range []string{"heartbeat", "offline", "new_login", "rebound", "source_changed", "unknown"} {
		t.Run(name, func(t *testing.T) {
			s := base
			switch name {
			case "heartbeat":
				s.ConfirmedAt = now.Add(time.Second)
			case "offline":
				s.EndedAt = now
			case "new_login":
				s.ID = "s2"
			case "rebound":
				s.IP = "192.0.2.2"
			case "source_changed":
				s.Source = "other"
			case "unknown":
				s.IdentityIssue = "source_unavailable"
			}
			err := ValidateSessionApproval("a", approved, []Session{s}, now.Add(time.Second))
			want := name == "heartbeat" || name == "offline"
			if (err == nil) != want {
				t.Fatalf("unexpected approval: %v", err)
			}
		})
	}
	if err := ValidateSessionApproval("a", nil, []Session{base}, now); err == nil {
		t.Fatal("missing approval accepted")
	}
}
