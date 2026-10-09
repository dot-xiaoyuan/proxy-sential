package store

import (
	"context"
	"os"
	"proxy-sentinel/internal/normalized"
	"strconv"
	"testing"
	"time"
)

func TestAccountSnapshotProjectionDualStackAndMonotonicScope(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	loginAt := time.Unix(at.Add(-time.Hour).Unix(), 0).UTC()
	scope := IdentityScope{Source: "srun4k:account-replay", SensorID: "account-replay"}
	makeSnapshot := func(id string, stamp time.Time, addresses ...string) IdentitySnapshot {
		snap := IdentitySnapshot{IdentityScope: scope, SnapshotID: id, ObservedAt: stamp, IntervalSeconds: 60, Events: []normalized.Event{}}
		for _, ip := range addresses {
			snap.Events = append(snap.Events, normalized.Event{EventID: id + ip, Type: "identity", Timestamp: stamp.Format(time.RFC3339Nano), Source: scope.Source, Observer: map[string]any{"sensor_id": scope.SensorID}, Subject: map[string]any{"account_id": "account-replay", "ip": ip, "entity_role": "endpoint"}, Payload: map[string]any{"origin": scope.Source, "session_id": "login-generation-1", "session_status": "reconcile", "heartbeat_interval_seconds": "60"}})
		}
		for i := range snap.Events {
			snap.Events[i].Payload["source_login_generation"] = strconv.FormatInt(loginAt.Unix(), 10)
		}
		return snap
	}
	foreign := makeSnapshot("other-source", at, "192.0.2.58")
	foreign.Source = "srun4k:other-source"
	for i := range foreign.Events {
		foreign.Events[i].Source = foreign.Source
		foreign.Events[i].Payload["origin"] = foreign.Source
	}
	if _, err = pg.CommitIdentitySnapshot(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if err = pg.projectPendingIdentitySnapshots(ctx, 100); err != nil {
		t.Fatal(err)
	}
	for _, snap := range []IdentitySnapshot{makeSnapshot("dual", at, "192.0.2.57", "2001:db8::57"), makeSnapshot("heartbeat", at.Add(5*time.Second), "192.0.2.57", "2001:db8::57"), makeSnapshot("empty", at.Add(20*time.Second)), makeSnapshot("late", at.Add(10*time.Second), "192.0.2.57")} {
		if _, err = pg.CommitIdentitySnapshot(ctx, snap); err != nil {
			t.Fatal(err)
		}
		if err = pg.projectPendingIdentitySnapshots(ctx, 100); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := AccountSession{SessionID: "login-generation-1", AccountID: "account-replay", Source: scope.Source, CampusID: "other-campus", IP: "192.0.2.57", StartedAt: loginAt.Format(time.RFC3339Nano), LastConfirmedAt: at.Format(time.RFC3339Nano)}
	if err = writeIdentityState(ctx, tx, IdentityState{Sessions: []AccountSession{legacy}}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	profile, found, err := pg.GetAccountIdentity(ctx, "account-replay", Query{})
	if err != nil || !found || len(profile.Sessions) != 4 {
		t.Fatalf("dual stack missing: %+v %v %v", profile, found, err)
	}
	for _, session := range profile.Sessions {
		if session.EndedAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, session.EndedAt); err != nil {
				t.Fatalf("invalid session end timestamp: %s", session.EndedAt)
			}
		}
		if stamp, e := time.Parse(time.RFC3339Nano, session.StartedAt); e != nil || !stamp.Equal(loginAt) {
			t.Fatalf("snapshot reset login time: %+v", session)
		}
		if (session.Source == scope.Source && session.CampusID == "" && session.EndedAt == "") || (session.Source == foreign.Source && session.EndedAt != "") || session.MAC != "" || session.EndpointID != "" {
			t.Fatalf("resurrected or invented identity: %+v", session)
		}
	}
}
