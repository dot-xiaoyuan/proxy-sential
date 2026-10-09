package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestIEEE1905SnapshotRetiresOnlyReportedBSSPostgres(t *testing.T) {
	for _, mode := range []string{"empty", "subset", "fresh_positive", "other_gateway", "other_campus", "other_domain", "newer_join", "invalid", "zero_bss"} {
		t.Run(mode, func(t *testing.T) {
			s := activityV3PrivatePostgres(t)
			for _, name := range []string{"029_device_address_leases.sql", "074_ieee1905_client_associations.sql"} {
				raw, err := os.ReadFile("../../migrations/postgres/" + name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.pg.db.Exec(string(raw)); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			old := now.Add(-3 * time.Minute)
			fresh := now.Add(-time.Minute)
			const gateway = "20:3a:eb:e9:de:10"
			const bss = "02:00:00:00:00:02"
			_, err := s.pg.db.Exec(`INSERT INTO device_address_leases VALUES('office','campus','ack','192.0.2.22','mac:20:3a:eb:e9:de:10',$1,$2,'ack')`, now.Add(-time.Hour), now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			// Two clients on the reported BSS and one on an unrelated BSS.
			seedClients := []string{"02:00:00:00:00:01", "02:00:00:00:00:03", "02:00:00:00:00:05"}
			if mode == "fresh_positive" {
				seedClients = nil
			}
			for i, client := range seedClients {
				bssid := bss
				stamp := old
				if i == 2 {
					bssid = "02:00:00:00:00:04"
				}
				if mode == "newer_join" && i == 1 {
					stamp = now
				}
				_, err = s.pg.db.Exec(`INSERT INTO ieee1905_client_associations(sensor_id,campus_id,access_domain,gateway_ip,gateway_mac,bssid,client_mac,association_state,first_seen,last_seen,last_event_id) VALUES('office','campus','domain','192.0.2.22',$1,$2,$3,'joined',$4,$4,'original')`, gateway, bssid, client, stamp)
				if err != nil {
					t.Fatal(err)
				}
			}
			clients := []string{}
			if mode == "fresh_positive" {
				clients = []string{"02:00:00:00:00:01", "02:00:00:00:00:03"}
			}
			if mode == "subset" {
				clients = []string{"02:00:00:00:00:01"}
			}
			if mode == "invalid" {
				clients = []string{"invalid"}
			}
			snapshots := []map[string]any{{"bssid": bss, "client_macs": clients}}
			if mode == "zero_bss" {
				snapshots = []map[string]any{}
			}
			snapshotJSON, _ := json.Marshal(snapshots)
			row := map[string]any{"event_timestamp": fresh.Format(time.RFC3339Nano), "event_id": "snapshot", "sensor_id": "office", "campus_id": "campus", "access_domain": "domain", "gateway_mac": gateway, "source_event_type": "ieee1905_client_snapshot", "source": "packet-sidecar", "bss_snapshots_json": string(snapshotJSON)}
			switch mode {
			case "other_gateway":
				row["gateway_mac"] = "02:00:00:00:00:aa"
			case "other_campus":
				row["campus_id"] = "other"
			case "other_domain":
				row["access_domain"] = "other"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(row) }))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			s.ch = ch
			if err = s.syncIEEE1905Associations(context.Background(), "office", now.Add(-10*time.Minute), now); err != nil {
				t.Fatal(err)
			}
			totalExpected := 3
			if mode == "fresh_positive" {
				totalExpected = 2
			}
			expected := 3
			switch mode {
			case "empty":
				expected = 1
			case "subset", "newer_join", "fresh_positive":
				expected = 2
			}
			var joined, total int
			if err = s.pg.db.QueryRow(`SELECT count(*) FILTER(WHERE association_state='joined'),count(*) FROM ieee1905_client_associations`).Scan(&joined, &total); err != nil || joined != expected || total != totalExpected {
				t.Fatalf("snapshot scope incorrect: mode=%s joined=%d want=%d total=%d err=%v", mode, joined, expected, total, err)
			}
			// Replaying the same snapshot leaves counts stable and cannot erase a newer join.
			if err = s.syncIEEE1905Associations(context.Background(), "office", now.Add(-10*time.Minute), now); err != nil {
				t.Fatal(err)
			}
			if err = s.pg.db.QueryRow(`SELECT count(*) FILTER(WHERE association_state='joined') FROM ieee1905_client_associations`).Scan(&joined); err != nil || joined != expected {
				t.Fatalf("duplicate snapshot changed membership: %d %v", joined, err)
			}
		})
	}
}

func TestIEEE1905LeaveWinsAmbiguousSameBucketPostgres(t *testing.T) {
	s := activityV3PrivatePostgres(t)
	for _, name := range []string{"029_device_address_leases.sql", "074_ieee1905_client_associations.sql"} {
		raw, err := os.ReadFile("../../migrations/postgres/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.pg.db.Exec(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := ieee1905AssociationRow{Timestamp: now.Format(time.RFC3339Nano), EventID: "a-leave", SensorID: "office", GatewayMAC: "20:3a:eb:e9:de:10", BSSID: "02:00:00:00:00:02", ClientMAC: "02:00:00:00:00:01", State: "left", Source: "packet-sidecar"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(row)
		join := row
		join.EventID = "z-join"
		join.State = "joined"
		json.NewEncoder(w).Encode(join)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	s.ch = ch
	if err = s.syncIEEE1905Associations(context.Background(), "office", now.Add(-time.Minute), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = s.pg.db.QueryRow(`SELECT association_state FROM ieee1905_client_associations`).Scan(&state); err != nil || state != "left" {
		t.Fatalf("same-time join resurrected departed client: %s %v", state, err)
	}
}
