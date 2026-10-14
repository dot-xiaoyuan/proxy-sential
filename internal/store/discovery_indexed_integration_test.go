package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"proxy-sentinel/internal/discovery"
	"testing"
	"time"
)

func TestInventoryDiscoveryIndexedSchemaAndScope(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now().UTC()
	suffix := at.Format("150405.000000000")
	id := "indexed-scope:" + suffix
	obs := discovery.Observation{ID: id, EventID: id, Node: "sensor-a", Origin: "dhcp", MAC: "aa:bb:cc:dd:ee:77", IP: "192.0.2.177", Name: "schema-printer", ObservedAt: at, ValidUntil: at.Add(time.Hour)}
	raw, _ := json.Marshal(obs)
	if _, err = s.db.ExecContext(ctx, `INSERT INTO discovery_observation_latest(device_key,source_id,origin,service_type,port,id,observed_at,valid_until,withdrawn,data) VALUES($1,'test','dhcp','','',$1,$2,$3,false,$4)`, id, at, at.Add(time.Hour), raw); err != nil {
		t.Fatal(err)
	}
	// An identically named observation on another sensor must never join this lease.
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,endpoint_id,ip,action,observed_at,valid_until) VALUES('sensor-b','',$1,'mac:aa:bb:cc:dd:ee:77','192.0.2.177','ack',$2,$3)`, id, at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := discovery.Repository{DB: s.db}
	page, err := r.DevicesIndexed(ctx, discovery.DeviceQuery{Mode: "passive", Search: "schema-printer", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]discovery.DeviceView)
	if len(items) != 1 {
		t.Fatalf("items=%d", len(items))
	}
	for _, q := range []struct {
		search string
		count  int
	}{{"192.0.2.17", 0}, {"192.0.2.177", 1}, {"aa-bb-cc-dd-ee-77", 1}} {
		exact, e := r.DevicesIndexed(ctx, discovery.DeviceQuery{Mode: "passive", Search: q.search, Limit: 20})
		if e != nil {
			t.Fatal(e)
		}
		if len(exact["items"].([]discovery.DeviceView)) != q.count {
			t.Fatalf("exact search %s matched wrong addresses", q.search)
		}
	}
	if items[0].EndpointID != "" {
		t.Fatal("cross-sensor lease linked to device")
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role) VALUES('mac:aa:bb:cc:dd:ee:77','endpoint'); INSERT INTO endpoint_recognition_summary(endpoint_id,role,confidence,conflict) VALUES('mac:aa:bb:cc:dd:ee:77','printer',.95,false);`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,endpoint_id,ip,action,observed_at,valid_until) VALUES('sensor-a','',$1,'mac:aa:bb:cc:dd:ee:77','192.0.2.177','ack',now(),$2)`, id, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	page, err = r.DevicesIndexed(ctx, discovery.DeviceQuery{Mode: "passive", Search: "schema-printer", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items = page["items"].([]discovery.DeviceView)
	if len(items) != 1 || items[0].DeviceType != "printer" {
		t.Fatalf("recognition summary not used: %+v", items)
	}
}

func TestDeviceCenterIoTIndexedAdmissionAndCursor(t *testing.T) {
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
	at := time.Now().UTC()
	prefix := "center-iot-" + at.Format("150405.000000000")
	defer s.db.ExecContext(context.Background(), `DELETE FROM discovery_observation_latest WHERE source_id=$1`, prefix)
	add := func(id, origin, confidence string, withdrawn bool, stamp time.Time) {
		obs := discovery.Observation{ID: id, Node: prefix, Origin: origin, Confidence: confidence, Name: prefix, Capabilities: []string{"printing"}, ObservedAt: stamp, ValidUntil: stamp.Add(time.Hour), Withdrawn: withdrawn}
		raw, _ := json.Marshal(obs)
		if _, err := s.db.ExecContext(ctx, `INSERT INTO discovery_observation_latest(device_key,source_id,origin,service_type,port,id,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,'','',$1,$4,$5,$6,$7)`, id, prefix, origin, stamp, stamp.Add(time.Hour), withdrawn, raw); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < 80; n++ {
		add(fmt.Sprintf("%s-dhcp-%d", prefix, n), "dhcp", "confirmed", false, at)
	}
	add(prefix+"-withdrawn", "dns_sd", "strong", true, at)
	add(prefix+"-weak", "dns_sd", "clue", false, at)
	add(prefix+"-printer1", "dns_sd", "strong", false, at.Add(-time.Minute))
	add(prefix+"-printer2", "ssdp", "confirmed", false, at.Add(-2*time.Minute))
	repo := discovery.Repository{DB: s.db}
	query := discovery.DeviceQuery{Mode: "passive", View: "iot", Search: prefix, Limit: 1}
	page, err := repo.DevicesIndexed(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]discovery.DeviceView)
	if len(items) != 1 || items[0].ID != prefix+"-printer1" || page["has_more"] != true {
		t.Fatalf("wrong first IoT page: %+v", page)
	}
	query.Cursor = page["next_cursor"].(string)
	page, err = repo.DevicesIndexed(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	items = page["items"].([]discovery.DeviceView)
	if len(items) != 1 || items[0].ID != prefix+"-printer2" || page["has_more"] != false {
		t.Fatalf("wrong next IoT page: %+v", page)
	}
	query.View = ""
	if _, err = repo.DevicesIndexed(ctx, query); err == nil {
		t.Fatal("IoT cursor accepted on all discovery records")
	}
}
