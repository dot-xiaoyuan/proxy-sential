package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
)

func TestDiscoveryIndexedMetadataMatchesEveryCursorPage(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	prefix := "identity-count-" + now.Format("150405.000000000")
	macA, macB := "02:f0:00:00:00:01", "02:f0:00:00:00:02"
	custom := "registered:" + prefix
	defer s.db.Exec(`DELETE FROM endpoint_entities WHERE endpoint_id IN ($1,$2,$3)`, "mac:"+macA, "mac:"+macB, custom)
	defer s.db.Exec(`DELETE FROM discovery_observation_latest WHERE source_id=$1`, prefix)
	defer s.db.Exec(`DELETE FROM discovery_observations WHERE source_id=$1`, prefix)
	for endpoint, role := range map[string]string{"mac:" + macA: "printer", "mac:" + macB: "access_point", custom: "camera"} {
		if _, err = s.db.Exec(`INSERT INTO endpoint_entities(endpoint_id) VALUES($1)`, endpoint); err != nil {
			t.Fatal(err)
		}
		if _, err = s.db.Exec(`INSERT INTO endpoint_recognition_summary(endpoint_id,role,confidence,summary) VALUES($1,$2,.95,'{"device_type_confidence":0.95}')`, endpoint, role); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(id, key, origin, mac, ip, vlan, endpoint, kind string, caps []string) {
		t.Helper()
		observation := discovery.Observation{ID: prefix + id, SourceID: prefix, Node: "sensor", Site: "campus", Domain: prefix, VLAN: vlan, MAC: mac, IP: ip, Name: "shared-title", Origin: origin, DeviceType: kind, Capabilities: caps, Confidence: "strong", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
		raw, _ := json.Marshal(observation)
		if _, err = s.db.Exec(`INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,$6,false,$7)`, observation.ID, prefix+key, prefix, origin, now, observation.ValidUntil, raw); err != nil {
			t.Fatal(err)
		}
		if endpoint != "" {
			if _, err = s.db.Exec(`INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis) VALUES($1,$2,$3,'{}')`, observation.ID, endpoint, observation.ValidUntil); err != nil {
				t.Fatal(err)
			}
		}
	}
	// One trusted identity spans two discovery keys, protocols and address families.
	insert("a", "same-history", "ssdp", macA, "10.0.0.8", "10", "mac:"+macA, "", []string{"printing"})
	insert("b", "second-key", "ndp", macA, "fe80::8", "10", "", "", nil)
	// Different trusted identities may share the representative history key.
	insert("c", "same-history", "arp", macB, "10.0.0.8", "10", "", "", nil)
	insert("d", "scope-key", "dhcp", macA, "10.0.20.8", "20", "", "", nil)
	// A matching name/IP is insufficient to merge an unresolved service record.
	insert("e", "service-key", "dns_sd", "", "10.0.0.8", "10", "", "", nil)
	// A distinct registered endpoint remains separate even when the MAC matches.
	insert("f", "registered-key", "ws_discovery", macA, "10.0.0.8", "10", custom, "printer", nil)

	for _, age := range []time.Duration{48 * time.Hour, 31 * 24 * time.Hour} {
		past := now.Add(-age)
		id := prefix + age.String()
		observation := discovery.Observation{ID: id, SourceID: prefix, Node: "sensor", Domain: prefix, Origin: "arp", ObservedAt: past, ValidUntil: past.Add(time.Hour)}
		raw, _ := json.Marshal(observation)
		if _, err = s.db.Exec(`INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$1,$2,'arp',$3,$4,false,$5)`, id, prefix, past, observation.ValidUntil, raw); err != nil {
			t.Fatal(err)
		}
	}
	repo := discovery.Repository{DB: s.db}
	assert := func(q discovery.DeviceQuery, want int64) {
		t.Helper()
		q.Mode = "passive"
		q.Domain = prefix
		q.Limit = 1
		meta, err := repo.DevicesIndexedMetadata(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if meta.Total != want {
			t.Fatalf("query=%+v total=%d want=%d", q, meta.Total, want)
		}
		cursors := map[string]bool{}
		count := 0
		for pages := 0; pages < 10; pages++ {
			page, err := repo.DevicesIndexed(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			items := page["items"].([]discovery.DeviceView)
			count += len(items)
			if page["has_more"] != true {
				break
			}
			cursor := page["next_cursor"].(string)
			if cursor == "" || cursors[cursor] {
				t.Fatal("cursor did not advance")
			}
			cursors[cursor] = true
			q.Cursor = cursor
		}
		if int64(count) != meta.Total {
			t.Fatalf("count=%d disagrees with metadata=%d for %+v", count, meta.Total, q)
		}
	}
	assert(discovery.DeviceQuery{}, 5)
	assert(discovery.DeviceQuery{Window: -1}, 6)
	assert(discovery.DeviceQuery{Window: 720 * time.Hour}, 6)
	assert(discovery.DeviceQuery{DeviceType: "printer"}, 2)
	assert(discovery.DeviceQuery{DeviceType: "access_point", Category: "network"}, 1)
	assert(discovery.DeviceQuery{Protocol: "ndp"}, 1)
	assert(discovery.DeviceQuery{Capability: "dumb"}, 1)
	assert(discovery.DeviceQuery{View: "iot", Category: "printer"}, 1)
	assert(discovery.DeviceQuery{State: "candidate"}, 1)
	assert(discovery.DeviceQuery{State: "conflict"}, 1)
	assert(discovery.DeviceQuery{VLAN: "20"}, 1)
	assert(discovery.DeviceQuery{Search: "shared-title"}, 5)
	assert(discovery.DeviceQuery{Search: "nothing-matches"}, 0)
}
