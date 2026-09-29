package store

import (
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestDeviceNameReplay(t *testing.T) {
	at := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	event := normalized.Event{EventID: "e1", Type: "device", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "lab"}, Subject: map[string]any{"ip": "192.0.2.1", "mac": "aa:bb:cc:dd:ee:01"}, Payload: map[string]any{"origin": "dhcp", "hostname": "Laptop", "client_fqdn": "Laptop.example."}}
	names := extractDeviceNames(event)
	if len(names) != 2 {
		t.Fatalf("DHCP names: %+v", names)
	}
	got := selectDeviceName(names, "", at)
	if got.Value != "Laptop.example" || got.Source != "dhcp_fqdn" {
		t.Fatalf("selection: %+v", got)
	}
	if selectDeviceName(names, "备注", at).Value != "备注" {
		t.Fatal("manual priority")
	}
	if selectDeviceName(names, "", at.Add(8*24*time.Hour)).Status != "historical" {
		t.Fatal("expiration")
	}
	event.Payload = map[string]any{"origin": "mdns", "name": "other.local", "query": "other.local"}
	if len(extractDeviceNames(event)) != 0 {
		t.Fatal("query claimed as name")
	}
	event.Payload = map[string]any{"origin": "mdns", "is_response": true, "record_type": "A", "record_name": "Laptop.local.", "record_address": "192.0.2.1", "record_ttl": float64(120)}
	names = extractDeviceNames(event)
	if len(names) != 1 || names[0].Address != "192.0.2.1" {
		t.Fatal(names)
	}
	if selectDeviceName(names, "", at.Add(121*time.Second)).Status != "historical" {
		t.Fatal("TTL ignored")
	}
	event.Payload["record_ttl"] = float64(0)
	withdrawn := extractDeviceNames(event)
	withdrawn[0].ObservedAt = at.Add(time.Second)
	withdrawn[0].EventID = "withdraw"
	if selectDeviceName(append(names, withdrawn...), "", at.Add(2*time.Second)).Status != "historical" {
		t.Fatal("withdrawal ignored")
	}
	delete(event.Payload, "record_address")
	if len(extractDeviceNames(event)) != 0 {
		t.Fatal("unaddressed response accepted")
	}
}
func TestDeviceNameDeterminism(t *testing.T) {
	now := time.Now().UTC()
	a := DeviceNameEvidence{Value: "a", Source: "dhcp_hostname", EventID: "a", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
	b := a
	b.Value = "b"
	b.EventID = "b"
	x, y := selectDeviceName([]DeviceNameEvidence{a, b}, "", now), selectDeviceName([]DeviceNameEvidence{b, a}, "", now)
	if x.Value != y.Value || x.Value != "b" || !x.MultipleNames {
		t.Fatalf("unstable: %+v %+v", x, y)
	}
	if normalizeDeviceName("bad\x00name") != "" {
		t.Fatal("control character accepted")
	}
}

func TestAutomaticDeviceNameQualityReplay(t *testing.T) {
	for _, value := range []string{"4853000c-1c0f-4133-8c69-69da2675d0d0.local", "4853000C-1C0F-4133-8C69-69DA2675D0D0.LOCAL.", "0123456789abcdef.local", "aa-bb-cc-dd-ee-ff.local", "192.168.0.30", "123456.local", "localhost", "localhost.localdomain", "ADY-AL00", "ICL-AL10", "HONOR-100", "_http._tcp.local", "bad/name.local"} {
		e := normalized.Event{EventID: "quality", Type: "device", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Payload: map[string]any{"origin": "dhcp", "hostname": value}}
		if got := extractDeviceNames(e); len(got) != 0 {
			t.Errorf("unusable name accepted %q: %+v", value, got)
		}
		if got := selectDeviceName([]DeviceNameEvidence{{Value: value, Source: "dhcp_hostname"}}, "", time.Now()); got != nil {
			t.Errorf("legacy name displayed %q", value)
		}
	}
	for _, value := range []string{"Desk_PC", "ZXSLC SR7410-20:3a:eb:e9:de:10", "DESKTOP-4853000C", "张三的电脑.local", "HP-123456", "workstation.example", "a"} {
		if !usableAutomaticDeviceName(value, "hostname") {
			t.Errorf("useful name rejected %q", value)
		}
	}
	if usableAutomaticDeviceName("4853000c-1c0f-4133-8c69-69da2675d0d0._http._tcp.local", "service") {
		t.Fatal("opaque service accepted")
	}
	if !usableAutomaticDeviceName("Office Printer._ipp._tcp.local", "service") {
		t.Fatal("useful service rejected")
	}
}

func TestMDNSRecordShapeReplay(t *testing.T) {
	for _, tc := range []struct{ typ, address, name string }{
		{"A", "2001:db8::1", "Laptop.local"}, {"AAAA", "192.0.2.1", "Laptop.local"},
		{"A", "127.0.0.1", "Laptop.local"}, {"AAAA", "::1", "Laptop.local"},
		{"A", "192.0.2.1", "Printer._ipp._tcp.local"},
	} {
		e := normalized.Event{EventID: "shape", Type: "device", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Payload: map[string]any{"origin": "mdns", "is_response": true, "record_type": tc.typ, "record_address": tc.address, "record_name": tc.name, "record_ttl": 120}}
		if got := extractDeviceNames(e); len(got) != 0 {
			t.Errorf("bad record accepted %+v", tc)
		}
	}
}

func TestMDNSDisplayKeepsRawEvidence(t *testing.T) {
	n := DeviceNameEvidence{Value: "zhangtekiiphone.LOCAL", Source: "mdns_hostname", ObservedAt: time.Now(), ValidUntil: time.Now().Add(time.Hour)}
	got := selectDeviceName([]DeviceNameEvidence{n}, "", time.Now())
	if got == nil || got.Value != "zhangtekiiphone" || n.Value != "zhangtekiiphone.LOCAL" {
		t.Fatal(got)
	}
	if got = selectDeviceName([]DeviceNameEvidence{n}, "My.local", time.Now()); got.Value != "My.local" {
		t.Fatal("manual modified")
	}
}
