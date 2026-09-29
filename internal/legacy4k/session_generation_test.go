package legacy4k

import (
	"testing"
	"time"
)

func TestOnlineLoginGenerationChangesIdentity(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	in := OnlineInventory{InstanceID: "boot", ObservedAt: at, Rows: []map[string]string{{"session_id": "same-id", "rad_online_id": "7", "user_name": "a", "ip": "192.0.2.1", "ip6": "2001:db8::1", "add_time": "100"}}}
	first, err := in.IdentityRecords()
	if err != nil || len(first) != 2 {
		t.Fatal(err)
	}
	if first[0]["session_id"] != first[1]["session_id"] || first[0]["source_session_id"] != "same-id" || first[0]["raw_online_id"] != "7" || first[0]["source_login_generation"] != "100" {
		t.Fatal("dual stack identity split or raw ID lost")
	}
	in.Rows[0]["bytes_in"] = "999"
	in.ObservedAt = at.Add(time.Second)
	heartbeat, err := in.IdentityRecords()
	if err != nil || heartbeat[0]["session_id"] != first[0]["session_id"] {
		t.Fatal("counter or heartbeat changed generation")
	}
	in.Rows[0]["add_time"] = "200"
	again, err := in.IdentityRecords()
	if err != nil || again[0]["session_id"] == first[0]["session_id"] {
		t.Fatal("relogin reused old identity")
	}
	for _, bad := range []string{"0", "-1", " 100", "100.1", "0100", "2000"} {
		in.Rows[0]["add_time"] = bad
		if _, err := in.IdentityRecords(); err == nil {
			t.Fatalf("accepted invalid login %q", bad)
		}
	}
}
