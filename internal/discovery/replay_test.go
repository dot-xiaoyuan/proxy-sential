package discovery

import (
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestServiceReplay(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ service, capability string }{{"_ipp._tcp", "printing"}, {"_ipps._tcp", "printing"}, {"_uscan._tcp", "scanning"}, {"_airplay._tcp", "casting"}, {"_googlecast._tcp", "casting"}} {
		e := normalized.Event{EventID: tc.service, Type: "discovery", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "a"}, Payload: map[string]any{"origin": "dns_sd", "service_type": tc.service, "is_response": true, "ttl": 120}, Subject: map[string]any{"ip": "192.0.2.1"}}
		o, err := FromEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		if len(o.Capabilities) != 1 || o.Capabilities[0] != tc.capability || o.DeviceType != "" {
			t.Fatalf("service is capability, not hardware proof: %+v", o)
		}
		e.Payload["is_response"] = false
		if _, err = FromEvent(e); err == nil {
			t.Fatal("query accepted")
		}
	}
}
func TestScopeAndExpiryReplay(t *testing.T) {
	at := time.Now().UTC()
	a := Observation{ID: "a", Site: "s", Domain: "d", VLAN: "10", MAC: "00:11:22:33:44:55", ObservedAt: at, ValidUntil: at.Add(time.Minute)}
	b := a
	b.VLAN = "20"
	if a.Key() == b.Key() {
		t.Fatal("cross VLAN merged")
	}
	b = a
	b.Site = "other"
	if a.Key() == b.Key() {
		t.Fatal("cross site merged")
	}
	if !a.Current(at) || a.Current(at.Add(time.Minute)) || a.Current(at.Add(-time.Second)) {
		t.Fatal("invalid time boundary")
	}
	a.Withdrawn = true
	if a.Current(at) {
		t.Fatal("withdrawal active")
	}
}
func TestTargets(t *testing.T) {
	c := ScanConfig{Allow: []string{"192.0.2.0/30"}, Exclude: []string{"192.0.2.2/32"}}
	v, err := c.Targets(nil)
	if err != nil || len(v) != 1 || v[0] != "192.0.2.1" {
		t.Fatalf("%v %v", v, err)
	}
	c.Allow = []string{"10.0.0.0/8"}
	if _, err = c.Targets(nil); err == nil {
		t.Fatal("oversize accepted")
	}
	c = ScanConfig{Allow: []string{"2001:db8::/64"}}
	v, err = c.Targets([]string{"2001:db8::1", "2001:db9::1"})
	if err != nil || len(v) != 1 {
		t.Fatalf("IPv6 enumeration: %v %v", v, err)
	}
	c = ScanConfig{Allow: []string{"fe80::/64"}, Addresses: []string{"fe80::1"}}
	if _, err = c.Targets(nil); err == nil {
		t.Fatal("link local without interface")
	}
}

func TestSensitiveAndProtocols(t *testing.T) {
	for _, p := range []string{"ipp", "ipps", "ssdp", "onvif"} {
		c := ScanConfig{Allow: []string{"192.0.2.0/30"}, Protocols: []string{p}, Sensitive: true}
		if c.Validate() == nil {
			t.Fatal("application probe allowed in sensitive profile")
		}
	}
	c := ScanConfig{Allow: []string{"192.0.2.0/30"}, Protocols: []string{"all-ports"}}
	if c.Validate() == nil {
		t.Fatal("unbounded protocol accepted")
	}
}
