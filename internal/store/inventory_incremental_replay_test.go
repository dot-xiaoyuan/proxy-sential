package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

func TestInventoryIncrementalBatchesAndCorrections(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := "incremental-batch:" + time.Now().Format("150405.000000000")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := s.db.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	drain := func() {
		t.Helper()
		for n := 0; n < 100; n++ {
			done, e := s.materializeNextInventory(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if !done {
				return
			}
		}
		t.Fatal("queue did not drain")
	}
	exec(`INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now()-interval '1 minute')`, id)
	drain()
	exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) SELECT $1||':'||n,$1,'batch-user','192.0.2.125','batch',now()-interval '1 minute',now()-interval '1 minute' FROM generate_series(1,601)n`, id)
	if _, err = s.materializeNextInventory(ctx); err != nil {
		t.Fatal(err)
	}
	var pending bool
	var count int
	if err = s.db.QueryRowContext(ctx, `SELECT processed_generation<dirty_generation FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("601-event batch marked complete after only 500 deltas")
	}
	drain()
	checkCount := func(want int) {
		t.Helper()
		if e := s.db.QueryRowContext(ctx, `SELECT observation_count FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind='ip' AND value='192.0.2.125' AND source='batch'`, id).Scan(&count); e != nil {
			t.Fatal(e)
		}
		if count != want {
			t.Fatalf("count=%d want=%d", count, want)
		}
	}
	checkCount(601)
	exec(`UPDATE identity_ip_mac_history SET identity_confidence=.92 WHERE endpoint_id=$1`, id)
	drain()
	checkCount(601)
	exec(`UPDATE identity_ip_mac_history SET ip='192.0.2.126' WHERE event_id=$1`, id+":1")
	drain()
	checkCount(600)
	exec(`DELETE FROM identity_ip_mac_history WHERE event_id=$1`, id+":2")
	drain()
	checkCount(599)
	exec(`UPDATE endpoint_entities SET owner_name='new owner' WHERE endpoint_id=$1`, id)
	drain()
	var owner string
	if err = s.db.QueryRowContext(ctx, `SELECT list_item->>'owner_name' FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, id).Scan(&owner); err != nil || owner != "new owner" {
		t.Fatalf("owner=%q error=%v", owner, err)
	}
}

func TestInventoryIncrementalRecoveryAndTimedFacts(t *testing.T) {
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
	id := "incremental-recovery:" + time.Now().Format("150405.000000000")
	other := id + ":other"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := s.db.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	drain := func() {
		t.Helper()
		for n := 0; n < 100; n++ {
			done, e := s.materializeNextInventory(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if !done {
				return
			}
		}
		t.Fatal("queue did not drain")
	}
	scalar := func(q string, args ...any) string {
		t.Helper()
		var v string
		if e := s.db.QueryRowContext(ctx, q, args...).Scan(&v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	exec(`INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now()-interval '1 hour'),($2,'endpoint',now()-interval '1 hour')`, id, other)
	drain()
	at := time.Now().UTC().Add(-time.Minute)
	exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) VALUES($1,$2,'shared','192.0.2.42','replay',$3,$3)`, id+":event", id, at)
	exec(`INSERT INTO identity_access_history(event_id,endpoint_id,account_id,access_id,source,first_seen,last_seen) VALUES($1,$2,'shared','AP-A','replay',$3,$3)`, id+":event", id, at)
	// A crash before publication rolls back both results and acknowledgements.
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.materializeInventoryDeltaTx(ctx, tx, id); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	if got := scalar(`SELECT count(*)::text FROM endpoint_inventory_associations WHERE endpoint_id=$1`, id); got != "0" {
		t.Fatal("uncommitted results escaped", got)
	}
	if got := scalar(`SELECT count(*)::text FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1`, id); got != "2" {
		t.Fatal("rollback lost pending changes", got)
	}
	drain()
	if got := scalar(`SELECT observation_count::text FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind='account' AND value='shared'`, id); got != "1" {
		t.Fatal("cross-table event counted twice", got)
	}
	// Replaying the same business fact is idempotent.
	exec(`UPDATE identity_ip_mac_history SET last_seen=last_seen WHERE endpoint_id=$1`, id)
	drain()
	if got := scalar(`SELECT observation_count::text FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind='account' AND value='shared'`, id); got != "1" {
		t.Fatal("duplicate changed count", got)
	}
	// Move both halves of an event: the old endpoint must lose its contribution.
	exec(`UPDATE identity_ip_mac_history SET endpoint_id=$2 WHERE event_id=$1`, id+":event", other)
	exec(`UPDATE identity_access_history SET endpoint_id=$2 WHERE event_id=$1`, id+":event", other)
	drain()
	if got := scalar(`SELECT count(*)::text FROM endpoint_inventory_accounts WHERE endpoint_id=$1`, id); got != "0" {
		t.Fatal("old endpoint retained account", got)
	}
	if got := scalar(`SELECT account_id FROM endpoint_inventory_accounts WHERE endpoint_id=$1`, other); got != "shared" {
		t.Fatal("new endpoint lost account", got)
	}
	// A future observation becomes queryable when due without another source event.
	future := time.Now().UTC().Add(time.Second)
	exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) VALUES($1,$2,'future','192.0.2.43','replay',$3,$3)`, id+":future", id, future)
	drain()
	if got := scalar(`SELECT count(*)::text FROM endpoint_inventory_accounts WHERE endpoint_id=$1`, id); got != "0" {
		t.Fatal("future event became current early", got)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(time.Until(future) + 20*time.Millisecond):
	}
	dbs := &DBStore{pg: s}
	if _, e = dbs.enqueueExpiredInventoryJobs(ctx, 1000); e != nil {
		t.Fatal(e)
	}
	drain()
	if got := scalar(`SELECT account_id FROM endpoint_inventory_accounts WHERE endpoint_id=$1`, id); got != "future" {
		t.Fatal("timer lost future observation", got)
	}
	// Session corrections replace their old IP and preserve explicit interval semantics.
	exec(`INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,source,started_at,ended_at,identity_confidence) VALUES($1,'session-user',$2,'192.0.2.44','session-source',$3,$4,.9)`, id+":session", id, at.Add(-time.Hour), at.Add(-time.Second))
	drain()
	exec(`UPDATE account_sessions SET ip='192.0.2.45',account_id='corrected-session' WHERE session_id=$1`, id+":session")
	drain()
	if got := scalar(`SELECT count(*)::text FROM endpoint_inventory_sessions WHERE endpoint_id=$1 AND ip='192.0.2.44'`, id); got != "0" {
		t.Fatal("corrected session kept old IP", got)
	}
	if got := scalar(`SELECT account_id FROM endpoint_inventory_sessions WHERE endpoint_id=$1 AND ip='192.0.2.45'`, id); got != "corrected-session" {
		t.Fatal("session correction missing", got)
	}
	exec(`DELETE FROM account_sessions WHERE session_id=$1`, id+":session")
	drain()
	if got := scalar(`SELECT count(*)::text FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND source='session-source'`, id); got != "0" {
		t.Fatal("withdrawn session kept associations", got)
	}
}

// This isolates historical depth; it is not the site 10x/24-hour capacity gate.
func TestInventoryIncrementalHistoryGrowth(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, size := range []int{1000, 3000, 10000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			id := fmt.Sprintf("incremental-growth:%d:%d", size, time.Now().UnixNano())
			exec := func(q string, args ...any) {
				t.Helper()
				if _, e := s.db.ExecContext(ctx, q, args...); e != nil {
					t.Fatal(e)
				}
			}
			drain := func() {
				t.Helper()
				for n := 0; n < 100; n++ {
					done, e := s.materializeNextInventory(ctx)
					if e != nil {
						t.Fatal(e)
					}
					if !done {
						return
					}
				}
				t.Fatal("queue did not drain")
			}
			exec(`INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now()-interval '1 minute')`, id)
			exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) SELECT $1||':'||n,$1,'growth-user','192.0.2.123','growth',now()-interval '2 hours',now()-interval '1 hour'+n*interval '1 microsecond' FROM generate_series(1,$2)n`, id, size)
			drain()
			exec(`ANALYZE endpoint_inventory_contributions`)
			samples := []time.Duration{}
			for n := 0; n < 20; n++ {
				start := time.Now()
				exec(`UPDATE identity_ip_mac_history SET identity_confidence=$2 WHERE event_id=$1`, id+":1", float64(n)/100)
				drain()
				samples = append(samples, time.Since(start))
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			var count int
			if e := s.db.QueryRowContext(ctx, `SELECT observation_count FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind='ip' AND source='growth'`, id).Scan(&count); e != nil || count != size {
				t.Fatalf("count=%d want=%d error=%v", count, size, e)
			}
			t.Logf("history=%d updates=%d p50=%s p95=%s max=%s", size, len(samples), samples[9], samples[18], samples[19])
		})
	}
}

func TestInventoryIncrementalSnapshotDisappearance(t *testing.T) {
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
	id := "incremental-snapshot:" + time.Now().Format("150405.000000000")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := s.db.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	drain := func() {
		t.Helper()
		for n := 0; n < 100; n++ {
			done, e := s.materializeNextInventory(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if !done {
				return
			}
		}
		t.Fatal("queue did not drain")
	}
	exec(`INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now()-interval '2 hours')`, id)
	drain()
	confirmed := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	doc := AccountSession{SessionID: id, EndpointID: id, AccountID: "snapshot-owner", IP: "192.0.2.72", Source: "snapshot-replay", StartedAt: confirmed.Add(-time.Hour).Format(time.RFC3339Nano), LastConfirmedAt: confirmed.Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(doc)
	exec(`INSERT INTO account_identity_session_projection(source,sensor_id,campus_id,access_domain,session_id,ip,account_id,confirmed_at,document) VALUES('snapshot-replay','sensor','campus','domain',$1,'192.0.2.72','snapshot-owner',$2,$3)`, id, confirmed, raw)
	drain()
	doc.EndedAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	raw, _ = json.Marshal(doc)
	exec(`UPDATE account_identity_session_projection SET confirmed_at=now(),document=$2 WHERE session_id=$1`, id, raw)
	drain()
	var actual time.Time
	var explicit bool
	if err = s.db.QueryRowContext(ctx, `SELECT confirmed_at,interval_explicit FROM endpoint_inventory_sessions WHERE endpoint_id=$1`, id).Scan(&actual, &explicit); err != nil || !actual.Equal(confirmed) || explicit {
		t.Fatalf("disappearance became fresh evidence: %s explicit=%v error=%v", actual, explicit, err)
	}
	exec(`DELETE FROM account_identity_session_projection WHERE session_id=$1`, id)
	drain()
	var count int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_inventory_accounts WHERE endpoint_id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("withdrawn snapshot account remained: %d %v", count, err)
	}
}

func TestInventoryIncrementalLostLeaseDoesNotPublish(t *testing.T) {
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
	id := "incremental-lease:" + time.Now().Format("150405.000000000")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := s.db.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	drain := func() {
		t.Helper()
		for n := 0; n < 100; n++ {
			done, e := s.materializeNextInventory(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if !done {
				return
			}
		}
		t.Fatal("queue did not drain")
	}
	exec(`INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now()-interval '1 hour')`, id)
	drain()
	block, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer block.Rollback()
	if _, e = block.ExecContext(ctx, `SELECT endpoint_id FROM endpoint_inventory_lookup WHERE endpoint_id=$1 FOR UPDATE`, id); e != nil {
		t.Fatal(e)
	}
	exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) VALUES($1,$1,'lease-user','192.0.2.61','lease',now()-interval '1 minute',now()-interval '1 minute')`, id)
	finished := make(chan error, 1)
	go func() { _, e := s.materializeNextInventory(ctx); finished <- e }()
	leased := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); time.Sleep(5 * time.Millisecond) {
		if e = s.db.QueryRowContext(ctx, `SELECT lease_owner<>'' FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&leased); e != nil {
			t.Fatal(e)
		}
		if leased {
			break
		}
	}
	if !leased {
		t.Fatal("worker did not claim fixture")
	}
	exec(`UPDATE endpoint_inventory_projection_jobs SET lease_owner='replacement',lease_until=now()+interval '1 minute' WHERE endpoint_id=$1`, id)
	if e = block.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = <-finished; e != nil {
		t.Fatal(e)
	}
	var pending bool
	var facts int
	if e = s.db.QueryRowContext(ctx, `SELECT processed_generation<dirty_generation FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&pending); e != nil || !pending {
		t.Fatal("lost lease consumed progress", e)
	}
	if e = s.db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_inventory_contributions WHERE endpoint_id=$1`, id).Scan(&facts); e != nil || facts != 0 {
		t.Fatal("lost lease published contributions", e)
	}
	exec(`UPDATE endpoint_inventory_projection_jobs SET lease_owner='',lease_until='epoch' WHERE endpoint_id=$1`, id)
	drain()
	if e = s.db.QueryRowContext(ctx, `SELECT observation_count FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind='ip'`, id).Scan(&facts); e != nil || facts != 1 {
		t.Fatal("lease retry lost or duplicated event", e)
	}
}
