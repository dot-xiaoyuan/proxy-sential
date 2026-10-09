package legacy4k

import (
	"testing"
	"time"
)

func TestOnlineSnapshotValidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	good := OnlineInventory{InstanceID: "redis-epoch", ObservedAt: now, Rows: []map[string]string{{"rad_online_id": "7", "user_name": "alice", "ip": "192.0.2.4", "user_mac": "00:11:22:33:44:55", "vlan_id": "108", "control_id": "9"}}}
	rows, err := good.IdentityRecords()
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if rows[0]["session_id"] != "redis-epoch:7" || rows[0]["source_session_id"] != "7" {
		t.Fatal(rows)
	}
	if rows[0]["vlan"] != "108" || rows[0]["control_id"] != "9" {
		t.Fatalf("4K strategy-match directory fields were dropped: %+v", rows[0])
	}
	for _, name := range []string{"missing_id", "invalid_ip", "duplicate", "missing_account", "missing_epoch"} {
		t.Run(name, func(t *testing.T) {
			in := good
			in.Rows = []map[string]string{{"rad_online_id": "7", "user_name": "alice", "ip": "192.0.2.4"}}
			switch name {
			case "missing_id":
				delete(in.Rows[0], "rad_online_id")
			case "invalid_ip":
				in.Rows[0]["ip"] = "bad"
			case "duplicate":
				in.Rows = append(in.Rows, in.Rows[0])
			case "missing_account":
				delete(in.Rows[0], "user_name")
			case "missing_epoch":
				in.InstanceID = ""
			}
			if _, err := in.IdentityRecords(); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	good.Rows = nil
	if rows, err := good.IdentityRecords(); err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("explicit complete empty inventory rejected", rows, err)
	}
}

func TestNativeIP6Field(t *testing.T) {
	in := OnlineInventory{InstanceID: "epoch", ObservedAt: time.Now().UTC(), Rows: []map[string]string{{"rad_online_id": "206", "session_id": "accounting-session", "user_name": "test", "ip": "192.0.2.7", "ip6": "2001:db8::7"}}}
	rows, err := in.IdentityRecords()
	if err != nil || len(rows) != 2 || rows[1]["ip"] != "2001:db8::7" {
		t.Fatalf("native ip6 omitted: %+v %v", rows, err)
	}
	in.Rows[0]["ipv6"] = "2001:db8::7"
	rows, err = in.IdentityRecords()
	if err != nil || len(rows) != 2 {
		t.Fatalf("alias counted twice: %+v %v", rows, err)
	}
	in.Rows[0]["ip6"] = "invalid"
	if _, err = in.IdentityRecords(); err == nil {
		t.Fatal("invalid native field silently ignored")
	}
}

func TestDualStackSnapshotKeepsBothAddresses(t *testing.T) {
	in := OnlineInventory{InstanceID: "epoch", ObservedAt: time.Now().UTC(), Rows: []map[string]string{{"rad_online_id": "7", "user_name": "test", "ip": "192.0.2.7", "ipv6": "2001:db8::7", "device_id": "endpoint"}}}
	rows, err := in.IdentityRecords()
	if err != nil || len(rows) != 2 {
		t.Fatalf("dual stack dropped address: %+v %v", rows, err)
	}
	if rows[0]["ip"] != "192.0.2.7" || rows[1]["ip"] != "2001:db8::7" || rows[0]["session_id"] != rows[1]["session_id"] || rows[0]["endpoint_id"] != rows[1]["endpoint_id"] {
		t.Fatal("split session or endpoint identity", rows)
	}
	in.Rows[0]["ipv6"] = "::ffff:192.0.2.7"
	if rows, err = in.IdentityRecords(); err != nil || len(rows) != 1 {
		t.Fatal("mapped duplicate not normalized", rows, err)
	}
	in.Rows[0]["ipv6"] = "::"
	if rows, err = in.IdentityRecords(); err != nil || len(rows) != 1 {
		t.Fatal("empty IPv6 sentinel rejected active IPv4", rows, err)
	}
	in.Rows[0]["ip"] = "0.0.0.0"
	in.Rows[0]["ipv6"] = "2001:db8::7"
	if rows, err = in.IdentityRecords(); err != nil || len(rows) != 1 || rows[0]["ip"] != "2001:db8::7" {
		t.Fatal("IPv6-only session lost", rows, err)
	}
	in.Rows[0]["ip"] = "192.0.2.7"
	in.Rows[0]["ipv6"] = "broken"
	if _, err = in.IdentityRecords(); err == nil {
		t.Fatal("malformed second address silently dropped")
	}
	in.Rows[0]["ipv6"] = "ff02::1"
	if _, err = in.IdentityRecords(); err == nil {
		t.Fatal("multicast identity accepted")
	}
}
