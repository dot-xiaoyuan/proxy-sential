package discovery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/census"
)

func TestIndexedOverviewFiltersShareSelectionAndCursor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	q := DeviceQuery{
		Mode: "passive", HardwareV2: true, SnapshotAt: now,
		LastSeenFrom: now.Add(-24 * time.Hour), LastSeenTo: now,
		Subnet: "2001:db8::/64", FirstSeenWithin: 168 * time.Hour,
	}
	selection, err := buildIndexedDeviceSelection(q)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"last_seen<", "first_seen>=", "= ANY(subnets)", "pg_input_is_valid"} {
		if !strings.Contains(selection.CTE, fragment) {
			t.Fatalf("selection missing %q", fragment)
		}
	}
	cursor, err := encodeIndexedDeviceCursor(selection.Query, DeviceView{ID: "one", LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	q = selection.Query
	q.Cursor = cursor
	q.Subnet = "2001:db8:0:1::/64"
	if _, err := decodeIndexedDeviceCursor(q); err == nil {
		t.Fatal("subnet switch accepted a stale cursor")
	}
	q.Subnet = "2001:db8::1/64"
	if _, err := buildIndexedDeviceSelection(q); err == nil {
		t.Fatal("noncanonical subnet was accepted")
	}
	q.Subnet = ""
	q.LastSeenTo = time.Time{}
	if _, err := buildIndexedDeviceSelection(q); err == nil {
		t.Fatal("incomplete range was accepted")
	}
}

func TestHardwareOverviewPostgresCountsAndFiltersScopedIdentities(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-2 * time.Minute)
	o := hardwareTestObservation(at)
	o.Origin, o.VLAN, o.IP = "arp", "30", "10.42.3.12"
	o.ValidUntil = at.Add(time.Hour)
	o.Evidence.Payload = nil
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO discovery_observation_latest VALUES($1,$2,$3,$4,$5,false,$6)",
		o.ID, o.Key(), o.Origin, o.ObservedAt, o.ValidUntil, raw); err != nil {
		t.Fatal(err)
	}
	identity := HardwareIdentityKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF, o.MAC)
	scope := census.ScopeKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF)
	if _, err := db.Exec(`INSERT INTO passive_hardware_current(identity_key,scope_key,device_key,sensor_id,campus_id,access_domain,vlan,mac,
 hardware_type,hardware_type_status,hardware_model_status,first_seen,last_seen,active_until,data)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'printer','identified','identified',$9,$9,$10,'{"manufacturer":"HP"}')`,
		identity, scope, o.Key(), o.Node, o.Site, o.Domain, o.VLAN, o.MAC, at, o.ValidUntil); err != nil {
		t.Fatal(err)
	}
	yesterday := at.Add(-24 * time.Hour)
	if _, err := db.Exec(`INSERT INTO passive_census_runtime(sensor_id,available_from,last_source_at) VALUES($1,$2,$3)`, o.Node, yesterday.Add(-time.Hour), at); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO passive_census_identifier_5m VALUES($1,$2,'mac',$3,$4,$4,'yesterday')`, yesterday.Truncate(5*time.Minute), scope, o.MAC, yesterday); err != nil {
		t.Fatal(err)
	}
	repo := Repository{DB: db, HardwareV2: true}
	query := DeviceQuery{Mode: "passive", Subnet: "10.42.3.0/24", Search: "HP", FirstSeenWithin: 168 * time.Hour,
		LastSeenFrom: at.Add(-time.Minute), LastSeenTo: at.Add(time.Minute)}
	result, err := repo.DevicesIndexedMetadata(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	stats := result.Overview
	if result.Total != 1 || stats == nil || stats.Active != 1 || stats.DumbTerminals != 1 || stats.NewSevenDays != 1 || stats.PreviousActive == nil || *stats.PreviousActive != 1 ||
		len(stats.Brands) != 1 || stats.Brands[0].Brand != "HP" || len(stats.Subnets) != 1 || stats.Subnets[0].Subnet != query.Subnet {
		t.Fatalf("metadata=%+v overview=%+v", result, stats)
	}
	page, err := repo.DevicesIndexed(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if items, ok := page["items"].([]DeviceView); !ok || len(items) != 1 {
		t.Fatalf("list did not match overview: %+v", page)
	}
}

func TestHardwareIdentityScopeKeepsAddressCluesSearchable(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-2 * time.Minute)
	insert := func(o Observation) {
		t.Helper()
		raw, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO discovery_observation_latest VALUES($1,$2,$3,$4,$5,false,$6)",
			o.ID, o.Key(), o.Origin, o.ObservedAt, o.ValidUntil, raw); err != nil {
			t.Fatal(err)
		}
	}
	device := hardwareTestObservation(at)
	device.ValidUntil, device.Origin, device.IP = at.Add(time.Hour), "arp", "192.168.1.1"
	insert(device)
	withoutVLAN := device
	withoutVLAN.ID, withoutVLAN.EventID, withoutVLAN.VLAN = "arp-no-vlan", "arp-no-vlan", ""
	insert(withoutVLAN)
	clue := device
	clue.ID, clue.EventID, clue.MAC, clue.Origin, clue.VLAN = "ssdp-1", "ssdp-1", "", "ssdp", "2809/7"
	insert(clue)
	clue.ID, clue.EventID, clue.VLAN = "ssdp-2", "ssdp-2", "2809/8"
	insert(clue)
	product := clue
	product.ID, product.EventID, product.Origin, product.IP = "snmp", "snmp", "snmp", "10.0.0.3"
	product.ProductClue = &IPProductClue{
		IP: product.IP, SensorID: product.Node, Site: product.Site, Domain: product.Domain, VLAN: product.VLAN,
		EventID: product.EventID, ObservedAt: at, Attribution: "response_ip", ProductStatus: "no_type_match", Manufacturer: "Fixture",
	}
	insert(product)
	service := clue
	service.ID, service.EventID, service.Origin, service.IP = "service", "service", "dns_sd", ""
	insert(service)

	repo := Repository{DB: db, HardwareV2: true}
	for _, tc := range []struct {
		scope, search string
		total         int
	}{
		{"", "", 6},
		{"devices", "", 4},
		{"devices", "192.168.1.1", 2},
		{"address_clues", "192.168.1.1", 2},
		{"address_clues", "10.0.0.3", 0},
	} {
		t.Run(tc.scope+"/"+tc.search, func(t *testing.T) {
			q := DeviceQuery{Mode: "passive", IdentityScope: tc.scope, Search: tc.search, Limit: 1}
			metadata, err := repo.DevicesIndexedMetadata(ctx, q)
			if err != nil || metadata.Total != int64(tc.total) {
				t.Fatalf("total=%d want=%d err=%v", metadata.Total, tc.total, err)
			}
			var count int
			for page := 1; page <= max(1, tc.total); page++ {
				position, err := repo.DevicesIndexedPosition(ctx, q, page)
				if err != nil {
					t.Fatal(err)
				}
				q.Cursor = position.Cursor
				result, err := repo.DevicesIndexed(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				items := result["items"].([]DeviceView)
				count += len(items)
				for _, item := range items {
					if tc.scope == "address_clues" && (item.MAC != "" || item.EndpointID != "" || item.PrimaryIP != tc.search) {
						t.Fatalf("unexpected address clue: %+v", item)
					}
				}
			}
			if count != tc.total {
				t.Fatalf("read %d rows, want %d", count, tc.total)
			}
		})
	}
}
