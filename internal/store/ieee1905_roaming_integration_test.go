package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func TestIEEE1905RoamingLeaveTargetsCurrentAssociationPostgres(t *testing.T) {
	for _, mode := range []string{"old_bss", "current_bss", "other_campus", "other_domain"} {
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
			if _, err := s.pg.db.Exec(`INSERT INTO device_address_leases VALUES('office','campus','lease','192.0.2.22','mac:20:3a:eb:e9:de:10',$1,$2,'ack')`, now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile("../../examples/router/ieee1905/client-roaming.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			events := []ieee1905AssociationRow{}
			for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				var event normalized.Event
				if err = json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatal(err)
				}
				row := ieee1905AssociationRow{Timestamp: now.Add(time.Duration(i-5) * time.Minute).Format(time.RFC3339Nano), EventID: event.EventID, SensorID: stringFromMap(event.Observer, "sensor_id"), CampusID: stringFromMap(event.Subject, "campus_id"), AccessDomain: stringFromMap(event.Payload, "access_domain"), GatewayMAC: stringFromMap(event.Subject, "mac"), BSSID: stringFromMap(event.Payload, "bssid"), ClientMAC: stringFromMap(event.Payload, "client_mac"), State: stringFromMap(event.Payload, "association_state"), Source: event.Source, SourceEventType: event.SourceEventType}
				if row.State == "left" {
					switch mode {
					case "current_bss":
						row.BSSID = "02:00:00:00:00:04"
					case "other_campus":
						row.CampusID = "other"
						row.BSSID = "02:00:00:00:00:04"
					case "other_domain":
						row.AccessDomain = "other"
						row.BSSID = "02:00:00:00:00:04"
					}
				}
				events = append(events, row)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, e := range events {
					json.NewEncoder(w).Encode(e)
				}
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			s.ch = ch
			if err = s.syncIEEE1905Associations(context.Background(), "office", now.Add(-10*time.Minute), now); err != nil {
				t.Fatal(err)
			}
			groups, err := s.activeIEEE1905AssociationGroups(context.Background(), "office", now.Add(-10*time.Minute), now)
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if mode == "current_bss" {
				want = 1
			}
			if len(groups) != 1 || len(groups[0].Clients) != want {
				t.Fatalf("late leave affected another association: mode=%s want=%d groups=%+v", mode, want, groups)
			}
		})
	}
}
