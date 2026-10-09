package store

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"

	"github.com/DATA-DOG/go-sqlmock"
	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestManagedSRunSnapshotReplaysWithoutInventingScope(t *testing.T) {
	for _, hours := range []int{6, 168} {
		t.Run(strconv.Itoa(hours), func(t *testing.T) {
			at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
			scope := IdentityScope{Source: "srun4k:office", SensorID: "srun4k-direct:office"}
			interval := hours * 3600
			var input, output bytes.Buffer
			// Replay the standard identity adapter, including a real NAS but no campus/domain.
			for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
				err := json.NewEncoder(&input).Encode(map[string]string{
					"source": scope.Source, "sensor_id": scope.SensorID,
					"timestamp": at.Format(time.RFC3339Nano), "entity_role": "endpoint",
					"account_id": "test-account", "session_id": "login-generation-1", "ip": ip,
					"nas_ip": "192.0.2.190", "product_id": "product-1", "group_id": "group-1", "vlan": "10",
					"session_status": "reconcile", "action": "reconcile",
					"heartbeat_interval_seconds": strconv.Itoa(interval), "reconcile_interval_seconds": strconv.Itoa(interval),
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := identityadapter.Convert(&input, &output, identityadapter.Options{Source: scope.Source, SensorID: scope.SensorID}); err != nil {
				t.Fatal(err)
			}
			snapshot := IdentitySnapshot{IdentityScope: scope, SnapshotID: "managed-replay", ObservedAt: at, IntervalSeconds: interval}
			decoder := json.NewDecoder(&output)
			for decoder.More() {
				var event normalized.Event
				if err := decoder.Decode(&event); err != nil {
					t.Fatal(err)
				}
				snapshot.Events = append(snapshot.Events, event)
			}
			rows := policyRows(snapshot.Events)
			if len(rows) != 2 {
				t.Fatalf("dual-stack records=%d", len(rows))
			}
			for _, row := range rows {
				if scopeOf(row) != scope || row.HeartbeatSeconds != interval || row.ReconcileSeconds != interval {
					t.Fatalf("identity scope or interval changed: %+v", row)
				}
			}
			if snapshot.Events[0].Payload["nas_ip"] != "192.0.2.190" {
				t.Fatal("NAS source evidence lost")
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`SELECT content_sha256 FROM identity_full_snapshots`).WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
			mock.ExpectExec(`INSERT INTO identity_full_snapshots`).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			created, err := (&PostgresStore{db: db}).CommitIdentitySnapshot(context.Background(), snapshot)
			if err != nil || !created {
				t.Fatalf("managed snapshot rejected: created=%t error=%v", created, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdentitySnapshotReplay(t *testing.T) {
	at := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	scope := IdentityScope{Source: "radius", SensorID: "sensor-a", CampusID: "east", AccessDomain: "wifi"}
	session := policy.Session{ID: "s1", AccountID: "alice", Source: scope.Source, SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: "192.0.2.1", StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}, HeartbeatSeconds: 600}
	other := session
	other.ID = "s2"
	other.SensorID = "sensor-b"
	snapshots := []IdentitySnapshot{{IdentityScope: scope, SnapshotID: "empty", ObservedAt: at.Add(time.Minute), IntervalSeconds: 60, Sessions: []policy.Session{}}}
	for _, tc := range []struct {
		at    time.Time
		state string
	}{{at.Add(30 * time.Second), "active"}, {at.Add(90 * time.Second), "ended"}} {
		got := reconcileIdentitySessions([]policy.Session{session, other}, snapshots, tc.at)
		for _, s := range got {
			if s.SensorID == "sensor-a" && s.State(tc.at) != tc.state {
				t.Fatalf("at %v: %+v", tc.at, s)
			}
			if s.SensorID == "sensor-b" && s.State(tc.at) != "active" {
				t.Fatal("snapshot crossed sensor scope")
			}
		}
	}
	// A late pre-snapshot fact must still be closed by the retained empty inventory.
	session.ConfirmedAt = at.Add(10 * time.Second)
	session.Confirmations = []time.Time{session.ConfirmedAt}
	got := reconcileIdentitySessions([]policy.Session{session}, snapshots, at.Add(90*time.Second))
	if len(got) != 1 || got[0].State(at.Add(90*time.Second)) != "ended" {
		t.Fatalf("late fact bypassed snapshot: %+v", got)
	}
}

func TestIdentitySnapshotFreshnessAndRecovery(t *testing.T) {
	at := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	scope := IdentityScope{Source: "radius", SensorID: "a", CampusID: "east", AccessDomain: "wifi"}
	online := policy.Session{ID: "s", AccountID: "alice", Source: scope.Source, SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: "192.0.2.1", StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}, HeartbeatSeconds: 60, Status: "reconcile"}
	snapshots := []IdentitySnapshot{{IdentityScope: scope, SnapshotID: "one", ObservedAt: at, IntervalSeconds: 60, Sessions: []policy.Session{online}}}
	// A fresh incremental heartbeat cannot conceal interrupted full reconciliation.
	heartbeat := online
	heartbeat.Status = "heartbeat"
	heartbeat.ConfirmedAt = at.Add(3 * time.Minute)
	heartbeat.Confirmations = []time.Time{heartbeat.ConfirmedAt}
	got := reconcileIdentitySessions([]policy.Session{heartbeat}, snapshots, heartbeat.ConfirmedAt)
	if len(got) != 1 || got[0].State(heartbeat.ConfirmedAt) != "unknown" {
		t.Fatalf("stale source trusted: %+v", got)
	}
	online.StartedAt = at.Add(4 * time.Minute)
	online.ConfirmedAt = online.StartedAt
	online.Confirmations = []time.Time{online.ConfirmedAt}
	snapshots = append(snapshots, IdentitySnapshot{IdentityScope: scope, SnapshotID: "two", ObservedAt: online.ConfirmedAt, IntervalSeconds: 60, Sessions: []policy.Session{online}})
	got = reconcileIdentitySessions([]policy.Session{heartbeat}, snapshots, online.ConfirmedAt)
	if len(got) != 1 || got[0].State(online.ConfirmedAt) != "active" {
		t.Fatalf("fresh snapshot failed recovery: %+v", got)
	}
	if len(got[0].IdentitySnapshotIDs) != 1 || got[0].IdentitySnapshotIDs[0] != "two" {
		t.Fatalf("identity snapshot provenance lost: %+v", got[0].IdentitySnapshotIDs)
	}
}

func TestIdentitySourceOutageDoesNotRewriteHistoricalAttribution(t *testing.T) {
	at := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	scope := IdentityScope{Source: "radius", SensorID: "a", CampusID: "east", AccessDomain: "wifi"}
	online := policy.Session{ID: "s", AccountID: "alice", Source: scope.Source, SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: "192.0.2.1", StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}, HeartbeatSeconds: 60, Status: "reconcile"}
	snapshots := []IdentitySnapshot{{IdentityScope: scope, ObservedAt: at, IntervalSeconds: 60, Sessions: []policy.Session{online}}}
	recovered := online
	recovered.ConfirmedAt = at.Add(10 * time.Minute)
	recovered.StartedAt = recovered.ConfirmedAt
	recovered.Confirmations = []time.Time{recovered.ConfirmedAt}
	snapshots = append(snapshots, IdentitySnapshot{IdentityScope: scope, ObservedAt: recovered.ConfirmedAt, IntervalSeconds: 60, Sessions: []policy.Session{recovered}})
	rows := reconcileIdentitySessions(nil, snapshots, at.Add(14*time.Minute))
	for _, tc := range []struct {
		minute int
		state  string
	}{{1, "resolved"}, {5, "unknown"}, {11, "resolved"}, {14, "unknown"}} {
		got := policy.Attribute(rows, scope.CampusID, scope.AccessDomain, online.IP, at.Add(time.Duration(tc.minute)*time.Minute))
		if got.State != tc.state {
			t.Fatalf("historical minute %d: %+v", tc.minute, got)
		}
	}
}
