package discovery

import (
	"slices"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestJoinedDNSModelRequiresTheOriginalTXTRecord(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	source := map[string]any{"content_sha256": hash, "ingest_source_ref": map[string]any{"file_id": "original"}}
	txt := map[string]any{"event_id": "zeek-" + hash[:24], "raw_ref": source}
	fact := HardwareFact{Source: "dns_sd", RawRef: map[string]any{"backend": "derived_dns_sd", "records": []any{txt, txt, nil}}}
	if fact.hasReferencedProductRecord() {
		t.Fatal("address reference treated as TXT")
	}
	fact.RawRef["records"] = []any{nil, nil, txt}
	if !fact.hasReferencedProductRecord() {
		t.Fatal("original joined TXT lost")
	}
	txt["record_type"] = "SRV"
	if fact.hasReferencedProductRecord() {
		t.Fatal("non-TXT admitted")
	}
}

func TestIEEE1905AdvancesActivityWithoutForgingHardwareType(t *testing.T) {
	base := time.Date(2026, 11, 24, 2, 49, 0, 0, time.UTC)
	fresh := base.Add(48 * time.Hour)
	arpObs := Observation{
		ID:         "arp-1",
		SourceID:   "passive:campus-204:enp3s0f0",
		Node:       "campus-204",
		Site:       "campus-204",
		Domain:     "enp3s0f0",
		VLAN:       "2809/4",
		IP:         "222.204.88.208",
		MAC:        "10:5d:dc:9b:13:b1",
		Origin:     "arp",
		ObservedAt: base,
		ValidUntil: base.Add(10 * time.Minute),
		Evidence:   normalized.Event{Subject: map[string]any{"mac": "10:5d:dc:9b:13:b1", "vlan": "2809/4"}, Payload: map[string]any{}},
	}
	ieeeObs := Observation{
		ID:         "ieee-1",
		SourceID:   "passive:campus-204:enp3s0f0",
		Node:       "campus-204",
		Site:       "campus-204",
		Domain:     "enp3s0f0",
		VLAN:       "2809/4",
		MAC:        "10:5d:dc:9b:13:b1",
		Origin:     "ieee1905",
		DeviceType: "access_point",
		ObservedAt: fresh,
		ValidUntil: fresh.Add(10 * time.Minute),
		Evidence:   normalized.Event{Subject: map[string]any{"mac": "10:5d:dc:9b:13:b1", "vlan": "2809/4"}, Payload: map[string]any{}},
	}
	arpFact, err := HardwareFactFromObservation(arpObs)
	if err != nil || arpFact == nil {
		t.Fatalf("expected arp fact, got %v %v", arpFact, err)
	}
	ieeeFact, err := HardwareFactFromObservation(ieeeObs)
	if err != nil || ieeeFact == nil {
		t.Fatalf("expected ieee1905 activity fact, got %v %v", ieeeFact, err)
	}
	if !ieeeFact.AddressOnly || len(ieeeFact.Signals) != 0 {
		t.Fatalf("ieee1905 must remain activity-only without product signals: %+v", ieeeFact)
	}
	state, err := EvaluateHardwareFacts([]HardwareFact{*arpFact, *ieeeFact}, nil, fresh.Add(time.Minute))
	if err != nil {
		t.Fatalf("evaluate facts: %v", err)
	}
	if !state.LastSeen.Equal(fresh) {
		t.Fatalf("expected last_seen=%s, got %s", fresh, state.LastSeen)
	}
	if state.HardwareType != "" || state.HardwareTypeStatus != "candidate" {
		t.Fatalf("ieee1905 must not forge confirmed hardware type: type=%q status=%q", state.HardwareType, state.HardwareTypeStatus)
	}

	// 采集范围存在异常或主 MAC 不一致时必须拒绝纳入硬件投影。
	badScope := ieeeObs
	badScope.Evidence.Observer = map[string]any{"capture_scope_issue": "vlan_mismatch"}
	if fact, err := HardwareFactFromObservation(badScope); err != nil || fact != nil {
		t.Fatalf("expected scoped issue to be rejected, got %+v %v", fact, err)
	}
	clientObs := Observation{
		ID:         "ieee-client-1",
		SourceID:   "passive:campus-204:enp3s0f0",
		Node:       "campus-204",
		Site:       "campus-204",
		Domain:     "enp3s0f0",
		VLAN:       "2809/4",
		MAC:        "00:11:22:33:44:55",
		Origin:     "ieee1905_client",
		ObservedAt: fresh,
		ValidUntil: fresh.Add(24 * time.Hour),
		Evidence:   normalized.Event{Subject: map[string]any{"mac": "00:11:22:33:44:55"}, Payload: map[string]any{"client_mac": "00:11:22:33:44:55"}},
	}
	clientFact, err := HardwareFactFromObservation(clientObs)
	if err != nil || clientFact == nil || !clientFact.AddressOnly || len(clientFact.Signals) != 0 {
		t.Fatalf("expected activity-only ieee1905_client fact, got %+v %v", clientFact, err)
	}
}

func TestHardwareV2QueryAdmitsIEEE1905ActivityWithoutChanging184Default(t *testing.T) {
	v2, err := buildIndexedDeviceSelection(DeviceQuery{HardwareV2: true, Mode: "passive", Search: "10:5d:dc:9b:13:b1"})
	if err != nil {
		t.Fatal(err)
	}
	hasIEEE1905 := func(args []any) bool {
		return slices.ContainsFunc(args, func(v any) bool {
			s, ok := v.(string)
			return ok && s == "ieee1905"
		})
	}
	if !hasIEEE1905(v2.Args) {
		t.Fatalf("expected passive hardware v2 query to admit ieee1905 origin, args=%v", v2.Args)
	}
	legacy, err := buildIndexedDeviceSelection(DeviceQuery{HardwareV2: false, Mode: "passive", Search: "10:5d:dc:9b:13:b1"})
	if err != nil {
		t.Fatal(err)
	}
	if hasIEEE1905(legacy.Args) {
		t.Fatalf("default 184 read path must not change origins, args=%v", legacy.Args)
	}
}

func TestSNMPSelfMACDirectHardwareOwnership(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	o := Observation{
		ID:         "snmp-self-1",
		EventID:    "snmp-self-1",
		SourceID:   "zeek",
		Node:       "campus-204",
		Site:       "campus-204",
		Domain:     "mirror",
		VLAN:       "4005",
		IP:         "10.131.253.10",
		MAC:        "aa:bb:cc:dd:ee:01",
		Origin:     "snmp",
		ObservedAt: now,
		ValidUntil: now.Add(24 * time.Hour),
		Evidence: normalized.Event{
			EventID: "snmp-self-1",
			Payload: map[string]any{
				"is_response":        true,
				"response_source_ip": "10.131.253.10",
				"snmp_self_mac":      "aa:bb:cc:dd:ee:01",
				"hardware_identity":  "snmp_self_mac",
				"system_description": "Ruijie 10G Ethernet Switch(S2910-24GT4XS-E) By Ruijie Networks",
			},
		},
	}
	fact, err := HardwareFactFromObservation(o)
	if err != nil || fact == nil || fact.MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("expected SNMP self-MAC hardware fact, got %+v %v", fact, err)
	}
	state, err := EvaluateHardwareFacts([]HardwareFact{*fact}, nil, now)
	if err != nil || state.HardwareType != "switch" || state.HardwareTypeStatus != "identified" {
		t.Fatalf("expected identified switch from SNMP self-MAC, got %+v %v", state, err)
	}

	// MAC 不一致时必须拒绝归属
	o.Evidence.Payload["snmp_self_mac"] = "11:22:33:44:55:66"
	if mismatch, err := HardwareFactFromObservation(o); err != nil || mismatch != nil {
		t.Fatalf("mismatched snmp_self_mac must be rejected, got %+v %v", mismatch, err)
	}
}
