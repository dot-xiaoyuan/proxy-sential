package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestIEEE1905GatewayRequiresCurrentUnambiguousLeasePostgres(t *testing.T) {
	for _, scenario := range []string{"valid", "expired", "released", "reassigned", "simultaneous_conflict", "moved", "multiple_current_ips", "other_campus", "other_sensor", "future_ack", "unverified_subject_ip"} {
		t.Run(scenario, func(t *testing.T) {
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
			at := now.Add(-time.Minute)
			const mac = "20:3a:eb:e9:de:10"
			ack := func(id, sensor, campus, ip, endpoint, action string, observed, until time.Time) {
				t.Helper()
				_, err := s.pg.db.Exec(`INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,observed_at,valid_until,action) VALUES($1,$2,$3,$4::inet,$5,$6,$7,$8)`, sensor, campus, id, ip, endpoint, observed, until, action)
				if err != nil {
					t.Fatal(err)
				}
			}
			observed, until := at.Add(-time.Minute), now.Add(time.Hour)
			campus, sensor := "campus-a", "office-30"
			switch scenario {
			case "expired":
				until = at
			case "other_campus":
				campus = "campus-b"
			case "other_sensor":
				sensor = "office-31"
			case "future_ack":
				observed = now
			}
			if scenario != "unverified_subject_ip" {
				ack("original", sensor, campus, "192.0.2.22", "mac:"+mac, "ack", observed, until)
			}
			switch scenario {
			case "released":
				ack("release", sensor, campus, "192.0.2.22", "mac:"+mac, "stop", at, at)
			case "reassigned":
				ack("replacement", sensor, campus, "192.0.2.22", "mac:02:00:00:00:00:aa", "ack", at, until)
			case "simultaneous_conflict":
				ack("conflict", sensor, campus, "192.0.2.22", "mac:02:00:00:00:00:aa", "ack", observed, until)
			case "moved":
				ack("move", sensor, campus, "192.0.2.23", "mac:"+mac, "ack", at, until)
			case "multiple_current_ips":
				ack("second", sensor, campus, "192.0.2.23", "mac:"+mac, "ack", observed, until)
			}
			row := ieee1905AssociationRow{Timestamp: at.Format(time.RFC3339Nano), EventID: "association", SensorID: "office-30", CampusID: "campus-a", GatewayMAC: mac, ClientMAC: "02:00:00:00:00:01", BSSID: "02:00:00:00:00:02", State: "joined", Source: "packet-sidecar"}
			if scenario == "unverified_subject_ip" {
				row.GatewayIP = "192.0.2.82"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(row)
				other := row
				other.ClientMAC = "02:00:00:00:00:03"
				other.EventID = row.EventID + "-2"
				json.NewEncoder(w).Encode(other)
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			s.ch = ch
			if err = s.syncIEEE1905Associations(context.Background(), row.SensorID, now.Add(-10*time.Minute), now); err != nil {
				t.Fatal(err)
			}
			groups, err := s.activeIEEE1905AssociationGroups(context.Background(), row.SensorID, now.Add(-10*time.Minute), now)
			if err != nil {
				t.Fatal(err)
			}
			expected := ""
			if scenario == "valid" {
				expected = "192.0.2.22"
			}
			if scenario == "moved" {
				expected = "192.0.2.23"
			}
			if expected == "" && len(groups) != 0 {
				t.Fatalf("%s attributed clients to stale/ambiguous IP: %+v", scenario, groups)
			}
			if expected != "" && (len(groups) != 1 || groups[0].GatewayIP != expected || len(groups[0].Clients) != 2) {
				t.Fatalf("valid lease lost: want=%s groups=%+v", expected, groups)
			}
			// The association itself remains available even when IP attribution fails.
			var count int
			if err = s.pg.db.QueryRow(`SELECT count(*) FROM ieee1905_client_associations`).Scan(&count); err != nil || count != 2 {
				t.Fatalf("raw association lost: %d %v", count, err)
			}
			if expected != "" {
				ack("later-release", row.SensorID, row.CampusID, expected, "mac:"+mac, "stop", now, now)
				groups, err = s.activeIEEE1905AssociationGroups(context.Background(), row.SensorID, now.Add(-10*time.Minute), now.Add(time.Second))
				if err != nil || len(groups) != 0 {
					t.Fatalf("quiet released association remained bound: %+v %v", groups, err)
				}
				row.Timestamp = now.Format(time.RFC3339Nano)
				row.EventID = "refresh"
				if err = s.syncIEEE1905Associations(context.Background(), row.SensorID, now.Add(-10*time.Minute), now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var ip string
				if err = s.pg.db.QueryRow(`SELECT COALESCE(host(gateway_ip),'') FROM ieee1905_client_associations`).Scan(&ip); err != nil || ip != "" {
					t.Fatal(fmt.Sprintf("released mapping retained: %q %v", ip, err))
				}
			}
		})
	}
}
