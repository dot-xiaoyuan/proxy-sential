package store

import (
	"context"
	"encoding/json"
	"os"
	"proxy-sentinel/internal/discovery"
	"testing"
	"time"
)

func TestDiscoveryIndexedFiltersUseSameIdentityAndEvidenceAsPage(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	key := "filter-replay-" + now.Format("150405.000000000")
	mac := "00:11:22:33:44:59"
	endpoint := "mac:" + mac
	defer s.db.Exec(`DELETE FROM discovery_observation_latest WHERE device_key=$1`, key)
	defer s.db.Exec(`DELETE FROM endpoint_entities WHERE endpoint_id=$1`, endpoint)
	_, err = s.db.Exec(`INSERT INTO endpoint_entities(endpoint_id,primary_mac) VALUES($1,$2)`, endpoint, mac)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`INSERT INTO endpoint_recognition_summary(endpoint_id,role,confidence,summary) VALUES($1,'access_point',.99,'{"device_type_confidence":0.95}') ON CONFLICT(endpoint_id) DO UPDATE SET role='access_point',confidence=.99,summary=excluded.summary`, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"arp", "dhcp"} {
		o := discovery.Observation{ID: key + origin, Origin: origin, MAC: mac, Node: "sensor-replay", Site: "campus", Domain: "domain-replay", VLAN: "20", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
		raw, _ := json.Marshal(o)
		_, err = s.db.Exec(`INSERT INTO discovery_observation_latest(device_key,source_id,origin,service_type,port,id,observed_at,valid_until,withdrawn,data) VALUES($1,$1,$2,'','',$3,$4,$5,false,$6)`, key, origin, o.ID, o.ObservedAt, o.ValidUntil, raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	repo := discovery.Repository{DB: s.db}
	q := discovery.DeviceQuery{Mode: "passive", Search: mac, DeviceType: "access_point", Protocol: "arp", State: "identified", Domain: "domain-replay", VLAN: "20", Limit: 1}
	page, err := repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]discovery.DeviceView)
	if len(items) != 1 || items[0].DeviceType != "access_point" || len(items[0].Protocols) != 2 {
		t.Fatalf("type/protocol filter discarded the linked evidence: %+v", items)
	}
	q.Domain = "other"
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 0 {
		t.Fatal("domain filter ignored")
	}
	q.Domain = "domain-replay"
	_, err = s.db.Exec(`UPDATE endpoint_recognition_summary SET summary='{"device_type_confidence":0.2}' WHERE endpoint_id=$1`, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 0 {
		t.Fatal("overall confidence promoted weak device type")
	}
	q.DeviceType = ""
	q.State = "candidate"
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 1 {
		t.Fatal("candidate state does not match effective type")
	}
	// A generic DHCP mobile family is compatible with a specific tablet role.
	if _, err = s.db.Exec(`UPDATE endpoint_recognition_summary SET role='tablet',summary='{"device_type_confidence":0.95}' WHERE endpoint_id=$1`, endpoint); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE discovery_observation_latest SET data=data || '{"device_type":"mobile","name":"replay-tablet"}' WHERE device_key=$1 AND origin='dhcp'`, key); err != nil {
		t.Fatal(err)
	}
	q.DeviceType = "tablet"
	q.State = "identified"
	q.Search = "replay-tablet"
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	items = page["items"].([]discovery.DeviceView)
	if len(items) != 1 || items[0].DeviceType != "tablet" || len(items[0].Protocols) != 2 {
		t.Fatalf("specific type or non-matching evidence lost: %+v", items)
	}
	q.DeviceType = "mobile"
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 0 {
		t.Fatal("obsolete generic type passed effective filter")
	}

	// Genuine conflicting types cannot pass either certain type filter.
	if _, err = s.db.Exec(`UPDATE discovery_observation_latest SET data=data || '{"device_type":"printer"}' WHERE device_key=$1 AND origin='dhcp'`, key); err != nil {
		t.Fatal(err)
	}
	q.DeviceType = "tablet"
	q.State = ""
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 0 {
		t.Fatal("conflicted tablet passed type filter")
	}
	q.DeviceType = ""
	q.State = "conflict"
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 1 {
		t.Fatal("conflict filter disagrees with page classification")
	}

	// An unrelated brand conflict must not discard a high-confidence type.
	if _, err = s.db.Exec(`UPDATE endpoint_recognition_summary SET role='printer',conflict=true,summary='{"device_type_confidence":0.95,"conflict_dimensions":["brand"]}' WHERE endpoint_id=$1`, endpoint); err != nil {
		t.Fatal(err)
	}
	q.DeviceType = "printer"
	q.State = "identified"
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 1 {
		t.Fatal("brand conflict suppressed an agreed type")
	}
	if _, err = s.db.Exec(`UPDATE endpoint_recognition_summary SET summary='{"device_type_confidence":0.95,"conflict_dimensions":["device_type"]}' WHERE endpoint_id=$1`, endpoint); err != nil {
		t.Fatal(err)
	}
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]discovery.DeviceView)) != 0 {
		t.Fatal("type conflict was presented as identified")
	}

	// Expired observations retain only a historical type and are separately filterable.
	expired := now.Add(-time.Minute)
	if _, err = s.db.Exec(`UPDATE discovery_observation_latest SET valid_until=$2,data=jsonb_set(data,'{valid_until}',to_jsonb($2::timestamptz)) WHERE device_key=$1`, key, expired); err != nil {
		t.Fatal(err)
	}
	q.State = "expired"
	page, err = repo.DevicesIndexed(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	items = page["items"].([]discovery.DeviceView)
	if len(items) != 1 || items[0].DeviceType != "" || items[0].LastDeviceType != "printer" {
		t.Fatalf("expired filter promoted type: %+v", items)
	}

}
