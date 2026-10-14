package store

import (
	"context"
	"fmt"
	"os"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestInventorySnapshotCursorEvidenceAndNoSyntheticIntervals(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	suffix := time.Now().Format("150405.000000000")
	id := "inventory-snapshot:" + suffix
	at := time.Now().UTC().Add(-48 * time.Hour)
	snap := IdentitySnapshot{IdentityScope: IdentityScope{Source: "srun4k:inventory-snapshot-" + suffix, SensorID: "test"}, SnapshotID: "old", ObservedAt: at, IntervalSeconds: 60}
	for n := 0; n < 2001; n++ {
		snap.Events = append(snap.Events, normalized.Event{EventID: fmt.Sprintf("%s-%d", suffix, n), Type: "identity", Timestamp: at.Format(time.RFC3339Nano), Source: snap.Source, Confidence: .9, Observer: map[string]any{"sensor_id": "test"}, Subject: map[string]any{"endpoint_id": id, "account_id": "snapshot-old", "entity_role": "endpoint", "ip": "192.0.2.88", "mac": "aa:bb:cc:00:01:02", "access_id": "AP-S"}, Payload: map[string]any{"origin": snap.Source, "session_id": fmt.Sprint(n), "session_status": "reconcile", "heartbeat_interval_seconds": "60"}})
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',now())`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CommitIdentitySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if err = s.backfillInventorySnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	busy, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = busy.ExecContext(ctx, `SELECT endpoint_id FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1 FOR UPDATE`, id); err != nil {
		busy.Rollback()
		t.Fatal(err)
	}
	started := time.Now()
	done, deferredErr := s.projectInventorySnapshotBatch(ctx)
	busy.Rollback()
	if deferredErr != nil || done || time.Since(started) > time.Second {
		t.Fatalf("contended snapshot did not defer promptly: done=%t err=%v", done, deferredErr)
	}
	var pendingCursor int
	if err = s.db.QueryRowContext(ctx, `SELECT event_cursor FROM endpoint_inventory_snapshot_jobs WHERE source=$1 AND snapshot_id='old' AND NOT processed`, snap.Source).Scan(&pendingCursor); err != nil || pendingCursor != 0 {
		t.Fatalf("deferred snapshot acknowledged unprocessed input: %d %v", pendingCursor, err)
	}
	if _, err = s.projectInventorySnapshotBatch(ctx); err != nil {
		t.Fatal(err)
	}
	var cursor int
	var processed bool
	if err = s.db.QueryRowContext(ctx, `SELECT event_cursor,processed FROM endpoint_inventory_snapshot_jobs WHERE source=$1 AND snapshot_id='old'`, snap.Source).Scan(&cursor, &processed); err != nil {
		t.Fatal(err)
	}
	if cursor != inventorySnapshotApplySize || processed {
		t.Fatalf("snapshot exceeded bounded batch: %d %t", cursor, processed)
	}
	// Recreate the worker and resume inside the staged 2,000-row parser chunk.
	resumed := &PostgresStore{db: s.db}
	for n := 1; n < (len(snap.Events)+inventorySnapshotApplySize-1)/inventorySnapshotApplySize; n++ {
		if _, err = resumed.projectInventorySnapshotBatch(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.db.QueryRowContext(ctx, `SELECT event_cursor,processed FROM endpoint_inventory_snapshot_jobs WHERE source=$1 AND snapshot_id='old'`, snap.Source).Scan(&cursor, &processed); err != nil || !processed || cursor != len(snap.Events) {
		t.Fatalf("snapshot resume incomplete: %d %t %v", cursor, processed, err)
	}
	// Retry completed jobs does not count the same snapshot again.
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_inventory_snapshot_jobs SET processed=false,event_cursor=0 WHERE source=$1`, snap.Source); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < (len(snap.Events)+inventorySnapshotApplySize-1)/inventorySnapshotApplySize; n++ {
		if _, err = s.projectInventorySnapshotBatch(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.projectPendingIdentitySnapshots(ctx, 10); err != nil {
		t.Fatal(err)
	}
	// A later empty snapshot marks absence, not a new observation of the old account.
	empty := snap
	empty.SnapshotID = "empty"
	empty.ObservedAt = time.Now().UTC().Add(-time.Minute)
	empty.Events = []normalized.Event{}
	if _, err = s.CommitIdentitySnapshot(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if err = s.projectPendingIdentitySnapshots(ctx, 10); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.materializeInventoryTx(ctx, tx, id); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_inventory_projection_state SET ready=true,backfill_complete=true`); err != nil {
		t.Fatal(err)
	}
	recent, err := s.ListDeviceInventory(ctx, Query{View: "recent", Window: "24h", Q: "192.0.2.88", InventorySearchType: "ip", InventorySkipMetadata: true})
	if err != nil || len(recent.Items) != 0 {
		t.Fatalf("snapshot absence manufactured recent occupancy: %+v %v", recent, err)
	}
	page, err := s.ListEndpointObservations(ctx, id, EndpointObservationQuery{Kind: "account", Value: "snapshot-old", Limit: 20})
	if err != nil || len(page.Items) != 20 {
		t.Fatalf("trace: %v", err)
	}
	for _, v := range page.Items {
		if v.StartedAt != "" || v.EndedAt != "" || v.EvidenceURL == "" {
			t.Fatal("synthetic interval or missing original snapshot entry")
		}
	}
	evidence, found, err := s.GetInventorySnapshotEvidence(ctx, id, page.Items[0].RecordID)
	if err != nil || !found || evidence.EventID == "" {
		t.Fatal("retained snapshot evidence missing", err)
	}
	if _, found, err = s.GetInventorySnapshotEvidence(ctx, "other", page.Items[0].RecordID); err != nil || found {
		t.Fatal("cross-endpoint snapshot evidence leaked")
	}
	var count int
	if err = s.db.QueryRowContext(ctx, `SELECT observation_count FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind='account' AND value='snapshot-old'`, id).Scan(&count); err != nil || count != 2001 {
		t.Fatalf("duplicate confirmations counted: %d %v", count, err)
	}
	if _, err = s.db.ExecContext(ctx, `DELETE FROM identity_full_snapshots WHERE source=$1 AND snapshot_id='old'`, snap.Source); err != nil {
		t.Fatal(err)
	}
	if _, found, err = s.GetInventorySnapshotEvidence(ctx, id, page.Items[0].RecordID); err != nil || found {
		t.Fatal("expired payload falsely available")
	}
	var factCount int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_inventory_snapshot_facts WHERE endpoint_id=$1`, id).Scan(&factCount); err != nil || factCount != 2001 {
		t.Fatal("expiration erased retained association facts")
	}
}
