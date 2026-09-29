package srunapi

import (
	"testing"
	"time"
)

func TestAccountDisconnectPlanStableAndSessionBound(t *testing.T) {
	now := time.Now().UTC()
	in := inventory(now)
	in.Rows = append(in.Rows, map[string]string{"session_id": "second", "rad_online_id": "43", "user_name": "test-user", "ip": "192.0.2.2", "add_time": "101"})
	plan, err := PlanAccountDisconnect(in, "test-user", "campus", "nas", now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sessions) != 2 || plan.Fingerprint == "" {
		t.Fatal("did not cover all sessions")
	}
	addresses := 0
	for _, s := range plan.Sessions {
		addresses += len(s.Addresses)
	}
	if addresses != 3 {
		t.Fatal("dual stack lost or counted as independent session")
	}
	in.Rows[0], in.Rows[1] = in.Rows[1], in.Rows[0]
	in.ObservedAt = now.Add(time.Second)
	in.Rows[0]["bytes_in"] = "100"
	same, err := PlanAccountDisconnect(in, "test-user", "campus", "nas", now.Add(time.Second), 30*time.Second)
	if err != nil || same.Fingerprint != plan.Fingerprint {
		t.Fatal("ordering or counters invalidated confirmation")
	}
	in.Rows = append(in.Rows, map[string]string{"add_time": "102", "session_id": "other", "rad_online_id": "44", "user_name": "other-account", "ip": "192.0.2.3"})
	same, err = PlanAccountDisconnect(in, "test-user", "campus", "nas", now.Add(time.Second), 30*time.Second)
	if err != nil || same.Fingerprint != plan.Fingerprint {
		t.Fatal("other account affected confirmation")
	}
	in.Rows[2]["user_name"] = "test-user"
	changed, err := PlanAccountDisconnect(in, "test-user", "campus", "nas", now.Add(time.Second), 30*time.Second)
	if err != nil || changed.Fingerprint == plan.Fingerprint {
		t.Fatal("new session did not require reconfirmation")
	}
}

func TestAccountDisconnectPlanRejectsAmbiguityAndDetectsScopeChanges(t *testing.T) {
	now := time.Now().UTC()
	base, _ := PlanAccountDisconnect(inventory(now), "test-user", "campus", "nas", now, 30*time.Second)
	for _, name := range []string{"stale", "duplicate", "empty_account", "missing_scope", "offline", "restart", "scope_changed", "binding_changed"} {
		t.Run(name, func(t *testing.T) {
			in := inventory(now)
			account, campus := "test-user", "campus"
			invalid := true
			switch name {
			case "stale":
				in.ObservedAt = now.Add(-time.Minute)
			case "duplicate":
				in.Rows = append(in.Rows, in.Rows[0])
			case "empty_account":
				account = ""
			case "missing_scope":
				campus = ""
			case "offline":
				in.Rows = nil
			case "restart":
				in.InstanceID = "new-boot"
				invalid = false
			case "scope_changed":
				campus = "other"
				invalid = false
			case "binding_changed":
				in.Rows[0]["add_time"] = "102"
				invalid = false
			}
			got, err := PlanAccountDisconnect(in, account, campus, "nas", now, 30*time.Second)
			if invalid {
				if err == nil {
					t.Fatal("invalid plan accepted")
				}
			} else if err != nil || got.Fingerprint == base.Fingerprint {
				t.Fatal("changed target scope retained confirmation")
			}
		})
	}
}
