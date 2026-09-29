package srunapi

import (
	"proxy-sentinel/internal/legacy4k"
	"testing"
	"time"
)

func inventory(at time.Time) legacy4k.OnlineInventory {
	return legacy4k.OnlineInventory{InstanceID: "redis-boot", ObservedAt: at, Rows: []map[string]string{{"session_id": "session-9", "rad_online_id": "42", "user_name": "test-user", "ip": "192.0.2.1", "ipv6": "2001:db8::1", "add_time": "100", "nas_ip": "192.0.2.254"}}}
}

func TestDisconnectOwnershipReplay(t *testing.T) {
	now := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	in := inventory(now)
	target, err := BindDisconnect(in, "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if target.RawOnlineID != "42" {
		t.Fatal("composite or accounting session ID used as native ID", target)
	}
	for _, tt := range []struct {
		name, want string
		change     func(*legacy4k.OnlineInventory)
	}{
		{"still_online", "online", func(*legacy4k.OnlineInventory) {}},
		{"offline", "absent", func(v *legacy4k.OnlineInventory) { v.Rows = nil }},
		{"restart", "unknown", func(v *legacy4k.OnlineInventory) { v.InstanceID = "new-boot"; v.Rows = nil }},
		{"account_rebound", "changed", func(v *legacy4k.OnlineInventory) { v.Rows[0]["user_name"] = "different-user" }},
		{"id_reused", "changed", func(v *legacy4k.OnlineInventory) { v.Rows[0]["add_time"] = "101" }},
		{"accounting_id_reused", "changed", func(v *legacy4k.OnlineInventory) { v.Rows[0]["rad_online_id"] = "43" }},
		{"ip_changed", "changed", func(v *legacy4k.OnlineInventory) { v.Rows[0]["ip"] = "192.0.2.2" }},
		{"native_ip6_changed", "changed", func(v *legacy4k.OnlineInventory) { v.Rows[0]["ip6"] = "2001:db8::2" }},
		{"stale", "unknown", func(v *legacy4k.OnlineInventory) { v.ObservedAt = now.Add(-time.Minute) }},
		{"future", "unknown", func(v *legacy4k.OnlineInventory) { v.ObservedAt = now.Add(time.Second) }},
		{"malformed_other_row", "unknown", func(v *legacy4k.OnlineInventory) {
			v.Rows = append(v.Rows, map[string]string{"rad_online_id": "other"})
		}},
		{"duplicate_native_id", "unknown", func(v *legacy4k.OnlineInventory) {
			v.Rows = append(v.Rows, map[string]string{"session_id": "second", "rad_online_id": "42", "user_name": "other", "ip": "192.0.2.5"})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := inventory(now)
			tt.change(&v)
			if got := CheckDisconnect(target, v, now, now, 30*time.Second); got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
	if got := CheckDisconnect(target, inventory(now), now.Add(time.Second), now, 30*time.Second); got != "unknown" {
		t.Fatal("pre-send observation accepted", got)
	}
}

func TestBindRequiresUniqueEventTimeSession(t *testing.T) {
	now := time.Now().UTC()
	for _, tt := range []struct{ account, session string }{{"other", legacy4k.OnlineSessionID("redis-boot", "session-9", "100")}, {"test-user", "session-9"}, {"test-user", "redis-boot:42"}} {
		if _, err := BindDisconnect(inventory(now), tt.account, tt.session, now, time.Minute); err == nil {
			t.Fatal("unbound target accepted", tt)
		}
	}
}

func TestAccountDisconnectDoesNotHideNewSessions(t *testing.T) {
	now := time.Now().UTC()
	in := inventory(now)
	target, err := BindDisconnect(in, "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, want  string
		rows        []map[string]string
		newSessions int
	}{
		{"all_gone", "completed", nil, 0},
		{"still_online", "pending", in.Rows, 0},
		{"new_login", "partial", []map[string]string{{"rad_online_id": "43", "session_id": "new-login", "user_name": "test-user", "ip": "192.0.2.1"}}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := inventory(now)
			v.Rows = tt.rows
			r := CheckAccountDisconnect([]DisconnectTarget{target}, v, now, now, time.Minute)
			if r.State != tt.want || len(r.NewSessions) != tt.newSessions {
				t.Fatalf("unexpected account result: %+v", r)
			}
		})
	}
	if r := CheckAccountDisconnect(nil, in, now, now, time.Minute); r.State != "unknown" {
		t.Fatal("empty intent accepted", r)
	}
	if r := CheckAccountDisconnect([]DisconnectTarget{target, target}, in, now, now, time.Minute); r.State != "unknown" {
		t.Fatal("duplicate intent accepted", r)
	}
}

func TestNativeDisconnectCannotInheritEarlierLoginApproval(t *testing.T) {
	now := time.Now().UTC()
	in := inventory(now)
	oldSession := legacy4k.OnlineSessionID(in.InstanceID, "session-9", "100")
	if _, err := BindDisconnect(in, "test-user", oldSession, now, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	in.Rows[0]["add_time"] = "101"
	if _, err := BindDisconnect(in, "test-user", oldSession, now, 30*time.Second); err == nil {
		t.Fatal("old approval rebound to a new login")
	}
	delete(in.Rows[0], "add_time")
	if _, err := BindDisconnect(in, "test-user", in.InstanceID+":session-9", now, 30*time.Second); err == nil {
		t.Fatal("missing login generation accepted for enforcement")
	}
}
