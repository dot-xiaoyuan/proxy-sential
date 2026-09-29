package policy

import "testing"

func TestSharedPolicyRejectsUnverifiedModesAndActions(t *testing.T) {
	for _, tc := range []struct {
		mode, action string
		ok           bool
	}{{"observe", "disconnect", true}, {"manual", "disconnect", true}, {"automatic", "disconnect", false}, {"manual", "notify", false}, {"manual", "rate_limit", false}, {"manual", "disable_account", false}} {
		p := Definition{ID: "shared", Name: "shared", Trigger: "shared_access", Mode: tc.mode, Stages: []Stage{{ConnectorID: "native", Action: tc.action, Template: "message", RateKbps: 100, DurationSeconds: 60}}}
		if err := p.Validate(); (err == nil) != tc.ok {
			t.Fatalf("%s/%s error=%v want valid=%v", tc.mode, tc.action, err, tc.ok)
		}
	}
}
