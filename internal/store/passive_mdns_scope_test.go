package store

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func TestMDNSScopeSurvivesCompactSubjectAndDerivedEvidence(t *testing.T) {
	var out bytes.Buffer
	raw := `{"ts":1785232800,"src_ip":"10.0.0.2","dst_ip":"224.0.0.251","src_mac":"00:11:22:33:44:55","capture_vlan":"2701/26","is_response":true,"record_type":"TXT","record_name":"TV._raop._tcp.local","record_text":"am=AppleTV3,1","record_ttl":120}`
	if _, err := zeek.Convert(strings.NewReader(raw+"\n"), &out, zeek.Options{LogKind: "mdns", SensorID: "sensor"}); err != nil {
		t.Fatal(err)
	}
	var e normalized.Event
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &e); err != nil {
		t.Fatal(err)
	}
	delete(e.Subject, "vlan") // ClickHouse discovery stream retains only compact subject.
	e.Payload["vrf"] = "blue"
	e.Payload["access_domain"] = "mirror"
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/24")
	at, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
	a, ok := passiveTXTObservation(e, "sensor", "mirror", "TV._raop._tcp.local", "am=AppleTV3,1", at, at.Add(time.Minute), scope)
	if !ok || a.VLAN != "2701/26" || a.VRF != "blue" || a.Evidence.Payload["vlan"] != "2701/26" {
		t.Fatalf("TXT lost scope: %+v", a)
	}
	e.Payload["vlan"] = "2701/27"
	b, _ := passiveTXTObservation(e, "sensor", "mirror", "TV._raop._tcp.local", "am=AppleTV3,1", at, at.Add(time.Minute), scope)
	if a.ID == b.ID {
		t.Fatal("cross-VLAN TXT merged")
	}
	p, _ := passivePTRObservation(e, "sensor", "mirror", "_raop._tcp.local", "TV._raop._tcp.local", at, at.Add(time.Minute), scope)
	if p.VLAN != "2701/27" || p.VRF != "blue" {
		t.Fatalf("PTR lost scope: %+v", p)
	}
	e.Payload["vlan"] = "2701/26"
	q, _ := passivePTRObservation(e, "sensor", "mirror", "_raop._tcp.local", "TV._raop._tcp.local", at, at.Add(time.Minute), scope)
	if p.ID == q.ID {
		t.Fatal("cross-VLAN PTR merged")
	}
	// An embedded third-party address cannot inherit the packet sender's MAC.
	third, _ := passiveTXTObservation(e, "sensor", "mirror", "TV(10.0.0.3)._raop._tcp.local", "am=AppleTV3,1", at, at.Add(time.Minute), scope)
	if third.MAC != "" {
		t.Fatalf("third-party address inherited responder MAC: %+v", third)
	}
}

func TestMDNSCoalescingKeepsSeparateScopes(t *testing.T) {
	base := normalized.Event{SourceEventType: "mdns", Observer: map[string]any{"sensor_id": "sensor", "interface": "mirror"}, Subject: map[string]any{"ip": "10.0.0.2"}, Payload: map[string]any{"is_response": true, "record_type": "TXT", "record_name": "tv._raop._tcp.local", "record_text": "am=AppleTV3,1", "vlan": "2701/26"}}
	other := base
	other.Payload = cloneMDNSPayload(base.Payload)
	other.Payload["vlan"] = "2701/27"
	if skipped := passiveCoalescedMDNSIndexes([]normalized.Event{base, other, base}); len(skipped) != 0 {
		t.Fatalf("cross-VLAN record coalesced: %v", skipped)
	}
	other.Payload["vlan"] = "2701/26"
	other.Payload["vrf"] = "blue"
	if skipped := passiveCoalescedMDNSIndexes([]normalized.Event{base, other, base}); len(skipped) != 0 {
		t.Fatalf("cross-VRF record coalesced: %v", skipped)
	}
}
