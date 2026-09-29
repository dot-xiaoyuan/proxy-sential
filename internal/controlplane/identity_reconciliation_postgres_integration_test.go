package controlplane

import (
	"context"
	"fmt"
	"os"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

func TestPreparedSnapshotFeedsPolicyIdentity(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	// Access the existing integration state only to clean this test's isolated scope.
	state, err := newIdentityIngestState("test", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	source := fmt.Sprintf("prepared-snapshot-%d", time.Now().UnixNano())
	defer state.db.ExecContext(context.Background(), `DELETE FROM identity_full_snapshots WHERE source=$1`, source)
	defer state.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE actor=$1`, "identity-integration:"+source)
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	one := 1
	request := identitySnapshotRequest{IdentityScope: store.IdentityScope{Source: source, SensorID: "test", CampusID: "east", AccessDomain: "wifi"}, ObservedAt: at, IntervalSeconds: 60, Complete: true, ExpectedCount: &one, Records: []map[string]string{{"session_id": "s", "account_id": "alice", "ip": "192.0.2.1"}}}
	snapshot, err := prepareIdentitySnapshot(request, "snapshot", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pg.CommitIdentitySnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	sessions, err := pg.ListPolicySessions(ctx, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, session := range sessions {
		if session.Source == source {
			found = true
			if session.State(at.Add(time.Second)) != "active" || session.EndpointID != "" {
				t.Fatalf("snapshot fabricated device or lost identity: %+v", session)
			}
		}
	}
	if !found {
		t.Fatal("no policy identity from complete snapshot")
	}
}

func TestDualStackSnapshotPolicyLifecycle(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	admin, err := newIdentityIngestState("test", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.db.Close()
	source := fmt.Sprintf("dualstack-%d", time.Now().UnixNano())
	defer admin.db.ExecContext(context.Background(), `DELETE FROM identity_full_snapshots WHERE source=$1`, source)
	defer admin.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE actor=$1`, "identity-integration:"+source)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	inv := legacy4k.OnlineInventory{InstanceID: "epoch", ObservedAt: at, Rows: []map[string]string{{"rad_online_id": "session", "user_name": source, "ip": "192.0.2.7", "ipv6": "2001:db8::7", "device_id": "one-endpoint"}}}
	commit := func(id string) {
		records, err := inv.IdentityRecords()
		if err != nil {
			t.Fatal(err)
		}
		count := len(records)
		snap, err := prepareIdentitySnapshot(identitySnapshotRequest{IdentityScope: store.IdentityScope{Source: source, SensorID: "lab", CampusID: "campus", AccessDomain: "nas"}, ObservedAt: inv.ObservedAt, IntervalSeconds: 60, Complete: true, ExpectedCount: &count, Records: records}, id, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pg.CommitIdentitySnapshot(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	read := func(at time.Time) []policy.Session {
		all, err := pg.ListPolicySessions(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		ss := []policy.Session{}
		for _, s := range all {
			if s.Source == source {
				ss = append(ss, s)
			}
		}
		return ss
	}
	commit("both")
	ss := read(at.Add(time.Second))
	if len(ss) != 2 {
		t.Fatal("address lost after database persistence", ss)
	}
	if q := policy.EvaluateQuota(source, ss, policy.Limits{}, at.Add(time.Second)); q.Total != 1 {
		t.Fatal("dual stack double-counted endpoint", q)
	}
	for _, ip := range []string{"192.0.2.7", "2001:db8::7"} {
		if a := policy.Attribute(ss, "campus", "nas", ip, at.Add(time.Second)); a.State != "resolved" || a.AccountID != source {
			t.Fatal(a)
		}
	}
	inv.ObservedAt = at.Add(30 * time.Second)
	delete(inv.Rows[0], "ipv6")
	commit("ipv4-only")
	ss = read(at.Add(31 * time.Second))
	if a := policy.Attribute(ss, "campus", "nas", "2001:db8::7", at.Add(time.Second)); a.State != "resolved" {
		t.Fatal("historical IPv6 attribution lost", a)
	}
	if a := policy.Attribute(ss, "campus", "nas", "2001:db8::7", at.Add(31*time.Second)); a.State == "resolved" {
		t.Fatal("removed IPv6 remains online", a)
	}
	if a := policy.Attribute(ss, "campus", "nas", "192.0.2.7", at.Add(31*time.Second)); a.State != "resolved" {
		t.Fatal("IPv6 removal closed IPv4", a)
	}
}
