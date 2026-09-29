package controlplane

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestApprovalFingerprintTracksMaterialChanges(t *testing.T) {
	now := time.Now().UTC()
	e := policy.Execution{ID: "round", AccountID: "a", Episode: 1, EvidenceIDs: []string{"e1"}, Definition: policy.Definition{ID: "p", Revision: 1, Stages: []policy.Stage{{Action: "disconnect", ConnectorID: "c"}}}, Stages: []policy.StageState{{Key: "stage", Status: "awaiting_approval"}}}
	session := policy.Session{ID: "s", AccountID: "a", Source: "auth", CampusID: "c", AccessDomain: "nas", IP: "192.0.2.1", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60}
	base, err := buildPolicyApprovalPreview(e, []policy.Session{session}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"heartbeat", "evidence", "policy", "episode", "session"} {
		t.Run(name, func(t *testing.T) {
			changed := e
			s := session
			switch name {
			case "heartbeat":
				s.ConfirmedAt = now.Add(time.Second)
			case "evidence":
				changed.EvidenceIDs = []string{"e2"}
			case "policy":
				changed.Definition.Revision++
			case "episode":
				changed.Episode++
			case "session":
				s.ID = "new-session"
			}
			got, err := buildPolicyApprovalPreview(changed, []policy.Session{s}, now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if (got.Fingerprint == base.Fingerprint) != (name == "heartbeat") {
				t.Fatal("incorrect confirmation invalidation")
			}
		})
	}
}
