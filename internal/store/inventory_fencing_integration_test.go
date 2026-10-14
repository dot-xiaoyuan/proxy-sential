package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestInventoryProjectionDoesNotBlockSourceAndFencesNewFacts(t *testing.T) {
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
	id := "inventory-fence:" + time.Now().Format("150405.000000000")
	at := time.Now().UTC().Add(-time.Minute)
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',$2)`, id, at); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) VALUES($1,$2,'older','192.0.2.60','fence',$3,$3)`, id+":old", id, at); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 20; n++ {
		if done, e := s.materializeNextInventory(ctx); e != nil {
			t.Fatal(e)
		} else if !done {
			break
		}
	}
	block, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	var locked string
	if err = block.QueryRowContext(ctx, `SELECT endpoint_id FROM endpoint_inventory_lookup WHERE endpoint_id=$1 FOR UPDATE`, id).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `SELECT enqueue_inventory_projection_id($1)`, id); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := s.materializeNextInventory(ctx); finished <- err }()
	leased := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); time.Sleep(5 * time.Millisecond) {
		if err = s.db.QueryRowContext(ctx, `SELECT lease_owner<>'' FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&leased); err != nil {
			t.Fatal(err)
		}
		if leased {
			break
		}
	}
	if !leased {
		t.Fatal("worker did not claim fixture")
	}
	start := time.Now()
	if _, err = s.db.ExecContext(ctx, `INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) VALUES($1,$2,'newer','192.0.2.61','fence',$3,$3)`, id+":new", id, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("heavy projection work blocked source notification")
	}
	if err = block.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	var pending bool
	var raw []byte
	if err = s.db.QueryRowContext(ctx, `SELECT processed_generation<dirty_generation FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&pending); err != nil || !pending {
		t.Fatal("new generation was incorrectly consumed", err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT list_item FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var old DeviceInventoryListItem
	_ = json.Unmarshal(raw, &old)
	if old.CurrentAccount != "older" {
		t.Fatal("unfenced generation committed")
	}
	if _, err = s.materializeNextInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT list_item FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &old)
	if old.CurrentAccount != "newer" {
		t.Fatal("retry lost new fact")
	}
}

// A live ingestion transaction can hold an existing job row for an entire
// authentication batch. Registering historical devices must not wait on it.
func TestInventoryBackfillSkipsLockedExistingJobs(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := "zz-seed-lock:" + time.Now().Format("150405.000000000")
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now())`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_inventory_projection_state SET cursor=$1,backfill_complete=false`, "zz-seed-lock:"); err != nil {
		t.Fatal(err)
	}
	lock, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `UPDATE endpoint_inventory_projection_jobs SET updated_at=now() WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if _, err = s.backfillInventoryBatch(bounded, 2000); err != nil {
		t.Fatalf("seed blocked by existing task: %v", err)
	}
}

func TestInventoryInitialBackfillRetainsConcurrentNotifications(t *testing.T) {
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
	// Existing fixture work is unrelated to this concurrency assertion.
	for n := 0; n < 100; n++ {
		done, e := s.materializeNextInventory(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if !done {
			break
		}
	}
	id := "initial-concurrent:" + time.Now().Format("150405.000000000")
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now());`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_inventory_lookup(endpoint_id,list_item) VALUES($1,'{}')`, id); err != nil {
		t.Fatal(err)
	}
	block, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	if _, err = block.ExecContext(ctx, `UPDATE endpoint_inventory_lookup SET updated_at=now() WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, e := s.materializeNextInventoryLane(ctx, "backfill"); finished <- e }()
	leased := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); time.Sleep(5 * time.Millisecond) {
		if err = s.db.QueryRowContext(ctx, `SELECT lease_owner<>'' FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&leased); err != nil {
			t.Fatal(err)
		}
		if leased {
			break
		}
	}
	if !leased {
		t.Fatal("initial job not leased")
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO identity_ip_mac_history(event_id,endpoint_id,ip,source,first_seen,last_seen) VALUES($1,$1,'192.0.2.73','initial-live',now(),now())`, id); err != nil {
		t.Fatal(err)
	}
	if err = block.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	var prepared, pending bool
	if err = s.db.QueryRowContext(ctx, `SELECT contributions_ready,processed_generation<dirty_generation FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&prepared, &pending); err != nil {
		t.Fatal(err)
	}
	if !prepared || !pending {
		t.Fatalf("initial result discarded or concurrent work lost: prepared=%v pending=%v", prepared, pending)
	}
	if _, err = s.materializeNextInventory(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRowContext(ctx, `SELECT observation_count FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind='ip' AND value='192.0.2.73'`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent initial observation count=%d: %v", count, err)
	}
}
