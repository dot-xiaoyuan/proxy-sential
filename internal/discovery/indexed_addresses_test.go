package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestHardwareIndexedRetainsLastScopedAddressAfterExpiry(t *testing.T) {
	db := hardwareIntegrationDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	type addressScenario struct {
		name, ip, vlan string
		age            time.Duration
		active         bool
	}
	scenarios := []addressScenario{
		{name: "expired-outside-window", ip: "192.0.2.1", vlan: "20", age: 36 * time.Hour},
		{name: "active", ip: "192.0.2.2", vlan: "20", age: 2 * time.Minute, active: true},
		{name: "same-ip-other-vlan", ip: "192.0.2.2", vlan: "21", age: 2 * time.Minute, active: true},
		{name: "reused-old", ip: "192.0.2.3", vlan: "20", age: 4 * time.Minute},
		{name: "reused-new", ip: "192.0.2.3", vlan: "20", age: 2 * time.Minute},
		{name: "released", ip: "192.0.2.4", vlan: "20", age: 4 * time.Minute},
	}
	expected := make(map[string]addressScenario, len(scenarios))
	for index, scenario := range scenarios {
		expected[scenario.name] = scenario
		address := hardwareTestObservation(now.Add(-scenario.age))
		address.ID = scenario.name + "-arp"
		address.MAC = fmt.Sprintf("00:11:22:33:44:%02x", index)
		address.VLAN = scenario.vlan
		address.IP = scenario.ip
		address.ValidUntil = address.ObservedAt.Add(10 * time.Minute)
		address.Origin, address.Confidence = "arp", "confirmed"
		address.Name, address.ModelName = "", ""
		address.Evidence = normalized.Event{}
		insert := func(o Observation) {
			t.Helper()
			raw, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,$3,$4,$5,$6,$7)`,
				o.ID, o.Key(), o.Origin, o.ObservedAt, o.ValidUntil, o.Withdrawn, raw); err != nil {
				t.Fatal(err)
			}
		}
		insert(address)
		notice := address
		notice.ID, notice.Origin, notice.IP, notice.Name = scenario.name+"-lldp", "lldp", "", scenario.name
		notice.ObservedAt, notice.ValidUntil = now.Add(-time.Minute), now.Add(time.Hour)
		insert(notice)
		switch scenario.name {
		case "expired-outside-window":
			foreign := address
			foreign.ID, foreign.Node, foreign.IP = "another-sensor", "another-sensor", "192.0.2.99"
			foreign.ObservedAt, foreign.ValidUntil = now.Add(-time.Minute), now.Add(time.Hour)
			insert(foreign)
			future := address
			future.ID, future.IP = "future-address", "192.0.2.98"
			future.ObservedAt, future.ValidUntil = now.Add(time.Minute), now.Add(time.Hour)
			insert(future)
		case "active":
			same := address
			same.ID, same.Origin = "same-address-dhcp", "dhcp"
			insert(same)
		case "released":
			release := address
			release.ID, release.Origin, release.Withdrawn = "address-release", "dhcp", true
			release.ObservedAt, release.ValidUntil = now.Add(-time.Minute), now.Add(-time.Minute)
			insert(release)
		}
	}
	repo := Repository{DB: db, HardwareV2: true}
	page, err := repo.DevicesIndexed(context.Background(), DeviceQuery{
		Mode: "passive", Protocol: "lldp", Window: 24 * time.Hour, SnapshotAt: now, Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]DeviceView)
	if len(items) != len(expected) {
		t.Fatalf("wanted %d devices, got %d", len(expected), len(items))
	}
	for _, item := range items {
		want, ok := expected[item.Name]
		if !ok {
			t.Fatalf("unexpected device %q", item.Name)
		}
		if item.LastObservedIP != want.ip || item.LastObservedIPAt == nil || !item.LastObservedIPAt.Equal(now.Add(-want.age)) {
			t.Errorf("%s last observed: %q at %v", item.Name, item.LastObservedIP, item.LastObservedIPAt)
		}
		current := []string{}
		if want.active {
			current = append(current, want.ip)
		}
		if item.CurrentAddresses == nil || !slices.Equal(*item.CurrentAddresses, current) {
			t.Errorf("%s current addresses: got %v want %v", item.Name, item.CurrentAddresses, current)
		}
	}
}
