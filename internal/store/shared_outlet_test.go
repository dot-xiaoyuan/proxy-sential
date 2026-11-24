package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOutletUsesOneAuthenticatedMACAcrossWindow(t *testing.T) {
	now := time.Now().UTC()
	m := sharedMapping()
	m.SensorID, m.CampusID, m.AccessDomain = "mirror", "ncu", "bond0"
	cfg := sharedaccess.Config{IdentityMappings: []sharedaccess.IdentityMapping{m}}
	w := sharedaccess.Window{IP: "192.0.2.4", SensorID: m.SensorID, CampusID: m.CampusID, AccessDomain: m.AccessDomain, From: now.Add(-time.Minute), To: now, LastObservedAt: now}
	cfg.IdentityMappings[0].ValidFrom = now.Add(-time.Hour)
	cfg.IdentityMappings[0].ValidUntil = now.Add(time.Hour)
	s := policy.Session{ID: "login1", AccountID: "account", IP: w.IP, Source: m.Source, SensorID: m.IdentitySensorID, CampusID: m.IdentityCampusID, AccessDomain: m.IdentityAccessDomain, MAC: "02:00:00:00:00:01", VLAN: "4", StartedAt: now.Add(-time.Hour), ConfirmedAt: now.Add(-2 * time.Minute), HeartbeatSeconds: 1800}
	if b := uniqueOutletSession(w, cfg, []policy.Session{s}); b == nil || b.MAC != s.MAC {
		t.Fatalf("missing binding: %+v", b)
	}
	other := s
	other.MAC = "02:00:00:00:00:02"
	if b := uniqueOutletSession(w, cfg, []policy.Session{s, other}); b != nil {
		t.Fatalf("conflicting MAC: %+v", b)
	}
	s.EndedAt = now.Add(-time.Second)
	if b := uniqueOutletSession(w, cfg, []policy.Session{s}); b != nil {
		t.Fatal("ended session")
	}
}

func TestMirrorClientTTLAndTLSWithoutUA(t *testing.T) {
	scope, cfg, rows, now := handshakeReplayFixture()
	for scenario, expect := range map[string]bool{"two_initial_families": true, "single_initial_family": false, "ua_only": false} {
		t.Run(scenario, func(t *testing.T) {
			samples := []sharedaccess.HandshakeSample{}
			for i := 0; i < 3; i++ {
				for j, ttl := range []uint8{62, 126} {
					at := now.Add(-time.Duration(20-i*5) * time.Second)
					value := strings.Repeat(string(rune('a'+j)), 32)
					family := "ja3"
					if scenario == "single_initial_family" {
						ttl = 63 - uint8(j)
					}
					if scenario == "ua_only" {
						family = "user_agent"
						value = []string{"Android", "Windows"}[j]
					}
					samples = append(samples, sharedaccess.HandshakeSample{EventID: fmt.Sprint(i, j), ObservedAt: at, DestinationPort: 443, Family: family, Value: value, ClientTTL: ttl})
				}
			}
			var payload map[string]any
			local := append([]sharedObservationEvent(nil), rows...)
			for i := range local {
				if local[i].IP != scope.IP {
					continue
				}
				if err := json.Unmarshal([]byte(local[i].Payload), &payload); err != nil {
					t.Fatal(err)
				}
				payload["feature_samples"] = samples
				raw, _ := json.Marshal(payload)
				local[i].Payload = string(raw)
			}
			w, item, err := buildHandshakeObservation(scope, cfg, local, now)
			if err != nil || slices.Contains(item.SignalGroups, "ttl_path") != expect || w.StrongAnchor != "" || item.Status == "confirmed" {
				t.Fatalf("signals=%v strong=%v err=%v", item.SignalGroups, w.StrongAnchor, err)
			}
		})
	}
}

func TestGatewayResolvesFromMappedAuthenticationWithoutDHCP(t *testing.T) {
	db, mock := newReconcileMock(t)
	to := reconcileObserved
	from := to.Add(-time.Minute)
	m := sharedMapping()
	m.SensorID, m.CampusID, m.AccessDomain = "mirror", "campus", "edge"
	m.ValidFrom, m.ValidUntil = from.Add(-time.Hour), to.Add(time.Hour)
	cfg := sharedaccess.Config{IdentityMappings: []sharedaccess.IdentityMapping{m}}
	w := sharedaccess.Window{SensorID: m.SensorID, CampusID: m.CampusID, AccessDomain: m.AccessDomain, From: from, To: to, LastObservedAt: from}
	const mac = "02:00:00:00:00:01"
	const ip = "10.157.2.191"
	first := from.Add(-time.Hour)
	mock.ExpectQuery("SELECT p.ip,coalesce").WithArgs(m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, "020000000001").WillReturnRows(sqlmock.NewRows([]string{"ip", "mac", "vlan", "period"}).AddRow(ip, mac, "4", 1800))
	log := sqlmock.NewRows([]string{"id", "at", "applied"}).AddRow("snapshot1", first, true).AddRow("snapshot2", from.Add(-time.Minute), true)
	raw, _ := json.Marshal(map[string]any{"session_id": "active", "account_id": "acct", "ip": ip, "mac": mac, "vlan": "4", "first_confirmed_at": first})
	members := sqlmock.NewRows([]string{"confirmed", "document"}).AddRow(first, raw)
	expectSharedIdentityReads(mock, from, to, log, members)
	b, found, err := (&DBStore{pg: &PostgresStore{db: db}}).lookupGatewayBinding(context.Background(), cfg, w, mac)
	if err != nil || !found || b == nil || b.IP != ip || b.Account != "acct" || b.VLAN != "4" {
		t.Fatalf("binding=%+v found=%v err=%v", b, found, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
