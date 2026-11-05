package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"proxy-sentinel/internal/pagination"
	"reflect"
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
	// A service may omit MAC while carrying the same canonical endpoint identity.
	insert("g", "canonical-service-key", "dns_sd", "", "fe80::9", "10", "mac:"+macA, "", nil)
	// Different trusted identities may share the representative history key.
	insert("c", "same-history", "arp", macB, "10.0.0.8", "10", "", "", nil)
	insert("d", "scope-key", "dhcp", macA, "10.0.20.8", "20", "", "", nil)
	insert("h", "other-scope-service-key", "dns_sd", "", "fe80::20", "20", "mac:"+macA, "", nil)
	// A matching name/IP is insufficient to merge an unresolved service record.
	insert("e", "service-key", "dns_sd", "", "10.0.0.8", "10", "", "", nil)
	// A distinct registered endpoint remains separate even when the MAC matches.
	insert("f", "registered-key", "ws_discovery", macA, "10.0.0.8", "10", custom, "printer", nil)
	insert("i", "registered-service-key", "dns_sd", "", "10.0.0.8", "10", custom, "", nil)
	// Invalid canonical formatting must stay an endpoint identity, not a MAC alias.
	insert("j", "malformed-endpoint-key", "dns_sd", "", "10.0.0.8", "10", "mac:02-f0-00-00-00-01", "", nil)

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
		expected := []discovery.DeviceView{}
		for pages := 0; pages < 10; pages++ {
			page, err := repo.DevicesIndexed(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			items := page["items"].([]discovery.DeviceView)
			count += len(items)
			expected = append(expected, items...)
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

		// Reverse page order exercises genuine random access rather than walking
		// cached cursors. Returned facts must match the corresponding keyset page.
		for number := len(expected); number >= 1; number-- {
			q.Cursor = ""
			pos, err := repo.DevicesIndexedPosition(ctx, q, number)
			if err != nil {
				t.Fatal(err)
			}
			q.Cursor = pos.Cursor
			got, err := repo.DevicesIndexed(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			items := got["items"].([]discovery.DeviceView)
			if len(items) != 1 || !reflect.DeepEqual(items[0], expected[number-1]) {
				t.Fatalf("page %d differs from sequential result: %+v", number, items)
			}
		}
		if _, err := repo.DevicesIndexedPosition(ctx, q, len(expected)+2); !errors.Is(err, pagination.ErrPageOutOfRange) {
			t.Fatalf("out-of-range position=%v", err)
		}
	}
	assert(discovery.DeviceQuery{}, 6)
	assert(discovery.DeviceQuery{Window: -1}, 7)
	assert(discovery.DeviceQuery{Window: 720 * time.Hour}, 7)
	assert(discovery.DeviceQuery{DeviceType: "printer"}, 2)
	assert(discovery.DeviceQuery{DeviceType: "access_point", Category: "network"}, 1)
	assert(discovery.DeviceQuery{Protocol: "ndp"}, 1)
	assert(discovery.DeviceQuery{Capability: "dumb"}, 1)
	assert(discovery.DeviceQuery{View: "iot", Category: "printer"}, 1)
	assert(discovery.DeviceQuery{State: "candidate"}, 2)
	assert(discovery.DeviceQuery{State: "conflict"}, 1)
	assert(discovery.DeviceQuery{VLAN: "20"}, 1)
	assert(discovery.DeviceQuery{Search: "shared-title"}, 6)
	assert(discovery.DeviceQuery{Search: "nothing-matches"}, 0)
	// Counting the canonical service with its MAC identity must also retain all
	// page evidence, including the original observation with no MAC field.
	page, err := repo.DevicesIndexed(ctx, discovery.DeviceQuery{Mode: "passive", Domain: prefix, VLAN: "10", DeviceType: "printer", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]discovery.DeviceView)
	if len(items) != 1 || items[0].EvidenceCount != 3 || len(items[0].Observations) != 3 || len(items[0].Addresses) != 3 || items[0].MAC != macA {
		t.Fatalf("canonical merge lost page evidence: %+v", items)
	}
	observedIDs := map[string]bool{}
	for _, observation := range items[0].Observations {
		observedIDs[observation.ID] = true
		if observation.ID == prefix+"g" && observation.MAC != "" {
			t.Fatal("derived canonical MAC overwrote service evidence")
		}
	}
	for _, id := range []string{"a", "b", "g"} {
		if !observedIDs[prefix+id] {
			t.Fatalf("missing canonical merge observation %s", id)
		}
	}

}
