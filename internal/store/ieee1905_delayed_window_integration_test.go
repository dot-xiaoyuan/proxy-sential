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

func TestIEEE1905DelayedWindowPreservesMembersAndAppliesLateNegativesPostgres(t *testing.T) {
	for _, mode := range []string{"refresh", "late_leave", "new_join", "empty_snapshot", "refresh_snapshot", "late_release", "legacy_before_lease", "preexisting_late_refresh", "preexisting_late_leave", "preexisting_scope_change"} {
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
			closed := now.Add(-2 * time.Minute)
			early := closed.Add(-time.Minute)
			late := now.Add(-time.Minute)
			_, err := s.pg.db.Exec(`INSERT INTO device_address_leases VALUES('office','campus','ack','192.0.2.22','mac:20:3a:eb:e9:de:10',$1,$2,'ack')`, func() time.Time {
				if mode == "legacy_before_lease" {
					return now.Add(-5 * time.Minute)
				}
				return now.Add(-time.Hour)
			}(), now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "late_release" {
				_, err = s.pg.db.Exec(`INSERT INTO device_address_leases VALUES('office','campus','release','192.0.2.22','mac:20:3a:eb:e9:de:10',$1,$1,'stop')`, late)
				if err != nil {
					t.Fatal(err)
				}
			}
			base := ieee1905AssociationRow{Timestamp: early.Format(time.RFC3339Nano), EventID: "early-a", SensorID: "office", CampusID: "campus", GatewayMAC: "20:3a:eb:e9:de:10", BSSID: "02:00:00:00:00:02", ClientMAC: "02:00:00:00:00:01", State: "joined", Source: "packet-sidecar"}
			events := []any{}
			for i, client := range []string{"02:00:00:00:00:01", "02:00:00:00:00:03"} {
				row := base
				row.ClientMAC = client
				if i == 1 {
					row.EventID = "early-b"
				}
				if mode != "new_join" {
					events = append(events, row)
				}
				if mode == "refresh" || mode == "new_join" {
					row.Timestamp = late.Format(time.RFC3339Nano)
					row.EventID = "late-" + row.EventID
					events = append(events, row)
				}
			}
			if mode == "late_leave" {
				row := base
				row.Timestamp = late.Format(time.RFC3339Nano)
				row.EventID = "late-leave"
				row.State = "left"
				events = append(events, row)
			}
			if mode == "empty_snapshot" || mode == "refresh_snapshot" {
				clients := []string{}
				if mode == "refresh_snapshot" {
					clients = []string{"02:00:00:00:00:01", "02:00:00:00:00:03"}
				}
				raw, _ := json.Marshal([]map[string]any{{"bssid": base.BSSID, "client_macs": clients}})
				events = append(events, map[string]any{"event_timestamp": late.Format(time.RFC3339Nano), "event_id": "late-snapshot", "sensor_id": "office", "campus_id": "campus", "gateway_mac": base.GatewayMAC, "source": "packet-sidecar", "source_event_type": "ieee1905_client_snapshot", "bss_snapshots_json": string(raw)})
			}
			if mode == "preexisting_late_refresh" || mode == "preexisting_late_leave" || mode == "preexisting_scope_change" {
				for _, client := range []string{"02:00:00:00:00:01", "02:00:00:00:00:03"} {
					_, err = s.pg.db.Exec(`INSERT INTO ieee1905_client_associations(sensor_id,campus_id,gateway_ip,gateway_mac,bssid,client_mac,association_state,first_seen,last_seen,last_event_id) VALUES('office','campus','192.0.2.22',$1,$2,$3,'joined',$4,$5,'old-tail')`, base.GatewayMAC, base.BSSID, client, early, late)
					if err != nil {
						t.Fatal(err)
					}
				}
				if mode == "preexisting_late_leave" {
					_, err = s.pg.db.Exec(`UPDATE ieee1905_client_associations SET association_state='left'`)
				} else if mode == "preexisting_scope_change" {
					_, err = s.pg.db.Exec(`UPDATE ieee1905_client_associations SET campus_id='other-campus'`)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "legacy_before_lease" {
				events = nil
				for i, client := range []string{"02:00:00:00:00:01", "02:00:00:00:00:03"} {
					at := early
					if i == 0 {
						at = now.Add(-10 * time.Minute)
					}
					_, err = s.pg.db.Exec(`INSERT INTO ieee1905_client_associations(sensor_id,campus_id,gateway_ip,gateway_mac,bssid,client_mac,association_state,first_seen,last_seen,last_event_id) VALUES('office','campus','192.0.2.22',$1,$2,$3,'joined',$4,$4,$5)`, base.GatewayMAC, base.BSSID, client, at, "legacy-"+client)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, row := range events {
					json.NewEncoder(w).Encode(row)
				}
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			s.ch = ch
			if err = s.syncIEEE1905Associations(context.Background(), "office", closed.Add(-10*time.Minute), now, closed); err != nil {
				t.Fatal(err)
			}
			groups, err := s.activeIEEE1905AssociationGroups(context.Background(), "office", closed.Add(-10*time.Minute), closed)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, group := range groups {
				count += len(group.Clients)
				if !group.LastSeen.Before(closed) {
					t.Fatalf("future observation entered closed window: %s", group.LastSeen)
				}
			}
			expected := 2
			switch mode {
			case "late_leave", "legacy_before_lease":
				expected = 1
			case "new_join", "empty_snapshot", "late_release", "preexisting_late_leave", "preexisting_scope_change":
				expected = 0
			}
			if count != expected {
				t.Fatalf("delayed window membership lost or late negative ignored: mode=%s count=%d want=%d groups=%+v", mode, count, expected, groups)
			}
		})
	}
}
