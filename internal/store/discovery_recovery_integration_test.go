package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func discoveryRecoveryFixture(t *testing.T) (*PostgresStore, discovery.Repository, string) {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required; not field acceptance")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("discovery-recovery-%d", time.Now().UnixNano())
	r := discovery.Repository{DB: pg.db, PipelineV2: true, ClaimSensor: prefix}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, q := range []string{
			`DELETE FROM discovery_device_changes_v2 WHERE document->'evidence'->'observer'->>'sensor_id'=$1`,
			`DELETE FROM discovery_service_facts_v2 WHERE sensor_id=$1`,
			`DELETE FROM discovery_device_state_v2 WHERE sensor_id=$1`,
			`DELETE FROM discovery_event_receipts WHERE sensor_id=$1`,
			`DELETE FROM discovery_normalized_receipts WHERE sensor_id=$1`,
			`DELETE FROM discovery_protocol_runtime WHERE sensor_id=$1`,
			`DELETE FROM discovery_recovery_manifest WHERE batch_id IN(SELECT batch_id FROM ingest_batches WHERE sensor_id=$1)`,
			`DELETE FROM discovery_cancel_manifest WHERE batch_id IN(SELECT batch_id FROM ingest_batches WHERE sensor_id=$1)`,
			`DELETE FROM discovery_batch_segments WHERE batch_id IN(SELECT batch_id FROM ingest_batches WHERE sensor_id=$1)`,
			`DELETE FROM discovery_batch_work WHERE batch_id IN(SELECT batch_id FROM ingest_batches WHERE sensor_id=$1)`,
			`DELETE FROM ingest_batches WHERE sensor_id=$1`,
		} {
			if _, e := pg.db.ExecContext(cleanup, q, prefix); e != nil {
				t.Errorf("fixture cleanup: %v", e)
			}
		}
		if e := r.UpdateDiscoveryStatistics(cleanup); e != nil {
			t.Errorf("fixture counter cleanup: %v", e)
		}
		pg.Close()
	})
	return pg, r, prefix
}

func TestDiscoveryCancelPreservesUnprocessedEvidence(t *testing.T) {
	pg, r, prefix := discoveryRecoveryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	batch := prefix + "-cancelled"
	if err := r.AcceptDiscoveryBatch(ctx, batch, []normalized.Event{recoveryFixtureEvent(prefix, prefix+"-cancel-event")}); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC()
	preview, err := r.CancelRecovery(ctx, prefix, cutoff, 500, false)
	if err != nil || preview.Batches != 1 || preview.Events != 1 {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	result, err := r.CancelRecovery(ctx, prefix, cutoff, 500, true)
	if err != nil || result.Batches != 1 || result.Events != 1 {
		t.Fatalf("cancel: %+v %v", result, err)
	}
	var preserved bool
	if err := pg.db.QueryRowContext(ctx, `SELECT w.lane='cancelled' AND NOT w.completed AND w.processed_offset=m.original_offset AND w.created_at=m.original_created_at AND w.error=m.original_error AND m.remaining_events=1 FROM discovery_batch_work w JOIN discovery_cancel_manifest m USING(batch_id) WHERE w.batch_id=$1`, batch).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("cancel changed original work: %v", err)
	}
	worked, err := r.ProcessDiscoveryBatch(ctx)
	if err != nil || worked {
		t.Fatalf("cancelled work was claimed: worked=%v err=%v", worked, err)
	}
}
func recoveryFixtureEvent(sensor, id string) normalized.Event {
	return normalized.Event{SchemaVersion: "v1", EventID: id, Type: "discovery", Source: "passive", SourceEventType: "ws_discovery", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "source_id": sensor, "interface": "test0"}, Subject: map[string]any{"site": "test", "domain": "test", "ip": "10.91.0.1"}, Payload: map[string]any{"origin": "ws_discovery", "is_response": true, "endpoint_reference": "camera", "types": "dn:NetworkVideoTransmitter", "ttl": 3600}}
}

func TestDiscoverySegmentCoalescesFactWritesWithoutLosingReceipts(t *testing.T) {
	pg, r, prefix := discoveryRecoveryFixture(t)
	r.Archive = func(context.Context, []normalized.Event) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	base := time.Now().UTC().Add(-time.Minute)
	events := make([]normalized.Event, 4)
	for i, suffix := range []string{"first", "repeat", "correction", "late"} {
		events[i] = recoveryFixtureEvent(prefix, prefix+"-"+suffix)
	}
	events[0].Timestamp = base.Format(time.RFC3339Nano)
	events[1].Timestamp = base.Add(time.Second).Format(time.RFC3339Nano)
	events[2].EventID = events[1].EventID
	events[2].Timestamp = base.Add(-time.Second).Format(time.RFC3339Nano)
	events[2].Payload = map[string]any{"origin": "ws_discovery", "is_response": true, "endpoint_reference": "camera", "ttl": 0, "withdrawn": true, "revision": 1}
	events[3].Timestamp = base.Add(-2 * time.Second).Format(time.RFC3339Nano)
	batch := prefix + "-coalesced"
	if err := r.AcceptDiscoveryBatch(ctx, batch, events); err != nil {
		t.Fatal(err)
	}
	if worked, err := r.ProcessDiscoveryBatch(ctx); err != nil || !worked {
		t.Fatalf("process: worked=%v err=%v", worked, err)
	}
	var count, revision int
	var eventID string
	var withdrawn bool
	if err := pg.db.QueryRowContext(ctx, `SELECT count(*),max(revision) FROM discovery_event_receipts WHERE sensor_id=$1`, prefix).Scan(&count, &revision); err != nil || count != 4 || revision != 1 {
		t.Fatalf("receipts=%d revision=%d err=%v", count, revision, err)
	}
	if err := pg.db.QueryRowContext(ctx, `SELECT event_id,revision,withdrawn FROM discovery_service_facts_v2 WHERE sensor_id=$1`, prefix).Scan(&eventID, &revision, &withdrawn); err != nil || eventID != events[2].EventID || revision != 1 || !withdrawn {
		t.Fatalf("winning fact=%q revision=%d withdrawn=%v err=%v", eventID, revision, withdrawn, err)
	}
	var late string
	if err := pg.db.QueryRowContext(ctx, `SELECT result FROM discovery_event_receipts WHERE sensor_id=$1 AND event_id=$2`, prefix, events[3].EventID).Scan(&late); err != nil || late != "late_history" {
		t.Fatalf("late receipt=%q err=%v", late, err)
	}
}

func TestDiscoveryRecoveryPostgresLeaseAndManifest(t *testing.T) {
	pg, r, prefix := discoveryRecoveryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	event := recoveryFixtureEvent(prefix, prefix+"-event")
	batch := prefix + "-batch"
	if err := r.AcceptDiscoveryBatch(ctx, batch, []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	// A replacement lease acquired while archive is in flight fences the old owner.
	r.Archive = func(c context.Context, _ []normalized.Event) error {
		_, err := pg.db.ExecContext(c, `UPDATE discovery_batch_work SET lease_token='replacement',lease_until=now()+interval '30 seconds' WHERE batch_id=$1`, batch)
		return err
	}
	if _, err := r.ProcessDiscoveryBatch(ctx); !errors.Is(err, discovery.ErrDiscoveryLeaseLost) {
		t.Fatalf("stale owner published: %v", err)
	}
	var token string
	var offset int
	if err := pg.db.QueryRowContext(ctx, `SELECT lease_token,processed_offset FROM discovery_batch_work WHERE batch_id=$1`, batch).Scan(&token, &offset); err != nil || token != "replacement" || offset != 0 {
		t.Fatalf("stale failure cleared lease: %s %d %v", token, offset, err)
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE discovery_batch_work SET lease_until=now()-interval '1 second',error='old_failure' WHERE batch_id=$1`, batch); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC()
	preview, err := r.MoveRecovery(ctx, prefix, cutoff, 1, false)
	if err != nil || preview.Batches < 1 {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	moved, err := r.MoveRecovery(ctx, prefix, cutoff, 500, true)
	if err != nil || moved.Batches < 1 {
		t.Fatalf("move: %+v %v", moved, err)
	}
	var preserved bool
	if err = pg.db.QueryRowContext(ctx, `SELECT w.created_at=m.original_created_at AND w.processed_offset=m.original_offset AND w.error=m.original_error AND NOT w.completed AND w.lane='backfill' FROM discovery_batch_work w JOIN discovery_recovery_manifest m USING(batch_id) WHERE w.batch_id=$1`, batch).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("move changed evidence: %v", err)
	}
	r.Archive = func(context.Context, []normalized.Event) error { return nil }
	if _, err = r.ProcessDiscoveryLane(ctx, "backfill"); err != nil {
		t.Fatal(err)
	}
	var receipts int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_event_receipts WHERE sensor_id=$1`, prefix).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("receipts %d %v", receipts, err)
	}
	if err = r.AcceptDiscoveryBatch(ctx, prefix+"-duplicate", []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ProcessDiscoveryBatch(ctx); err != nil {
		t.Fatal(err)
	}
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_event_receipts WHERE sensor_id=$1`, prefix).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("duplicate receipt %d %v", receipts, err)
	}
}

func TestDiscoveryRecoveryBeyondClickHouseWindow(t *testing.T) {
	chDSN := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if chDSN == "" {
		t.Skip("isolated ClickHouse required; not field acceptance")
	}
	pg, _, prefix := discoveryRecoveryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := ApplyClickHouseMigrations(ctx, chDSN, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: chDSN})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"normalized_events", "discovery_evidence_archive", "passive_discovery_events_v2"} {
			if e := ch.exec(context.Background(), "ALTER TABLE "+table+" DELETE WHERE sensor_id="+chQuote(prefix)+" SETTINGS mutations_sync=1"); e != nil {
				t.Errorf("ClickHouse fixture cleanup: %v", e)
			}
		}
	})
	writer := NewDiscoveryArchiveWriter(pg.db, ch)
	event := recoveryFixtureEvent(prefix, prefix+"-event")
	if err = writer.Write(ctx, []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	// Simulate the durable confirmation being lost after ClickHouse accepted it.
	if _, err = pg.db.ExecContext(ctx, `UPDATE discovery_normalized_receipts SET verified_at=NULL,resolve_after=now()-interval '1 second' WHERE sensor_id=$1`, prefix); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 110; i++ {
		filler := recoveryFixtureEvent(prefix, fmt.Sprintf("%s-fill-%d", prefix, i))
		if err = ch.insertNormalizedEvents(ctx, []normalized.Event{filler}); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Write(ctx, []normalized.Event{event}); err != nil {
		t.Fatalf("reconcile after block eviction: %v", err)
	}
	var receiptVersion string
	if err = pg.db.QueryRowContext(ctx, `SELECT xmin::text FROM discovery_normalized_receipts WHERE sensor_id=$1 AND event_id=$2`, prefix, event.EventID).Scan(&receiptVersion); err != nil {
		t.Fatal(err)
	}
	if err = writer.Write(ctx, []normalized.Event{event}); err != nil {
		t.Fatalf("cross-batch duplicate: %v", err)
	}
	var duplicateVersion string
	if err = pg.db.QueryRowContext(ctx, `SELECT xmin::text FROM discovery_normalized_receipts WHERE sensor_id=$1 AND event_id=$2`, prefix, event.EventID).Scan(&duplicateVersion); err != nil || duplicateVersion != receiptVersion {
		t.Fatalf("duplicate rewrote normalized receipt: before=%s after=%s err=%v", receiptVersion, duplicateVersion, err)
	}
	raw, err := ch.query(ctx, `SELECT count() n FROM normalized_events WHERE sensor_id=`+chQuote(prefix)+` AND event_id=`+chQuote(event.EventID)+` FORMAT JSONEachRow`)
	if err != nil {
		t.Fatal(err)
	}
	var counts []struct {
		N int `json:"n"`
	}
	if err = decodeJSONEachRow(raw, &counts); err != nil || len(counts) != 1 || counts[0].N != 1 {
		t.Fatalf("duplicate after recovery: %s %v", raw, err)
	}
	conflict := event
	conflict.Payload = map[string]any{"origin": "different"}
	if err = writer.Write(ctx, []normalized.Event{conflict}); !errors.Is(err, discovery.ErrDiscoveryContentConflict) {
		t.Fatalf("conflict not fenced: %v", err)
	}
}

func TestDiscoveryRecoveryLegacyProductReceipt(t *testing.T) {
	chDSN := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if chDSN == "" {
		t.Skip("isolated ClickHouse required")
	}
	pg, r, prefix := discoveryRecoveryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := ApplyClickHouseMigrations(ctx, chDSN, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: chDSN})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"normalized_events", "discovery_evidence_archive", "passive_discovery_events_v2"} {
			if err := ch.exec(context.Background(), "ALTER TABLE "+table+" DELETE WHERE sensor_id="+chQuote(prefix)+" SETTINGS mutations_sync=1"); err != nil {
				t.Error(err)
			}
		}
	})
	writer := NewDiscoveryArchiveWriter(pg.db, ch)
	r.Archive = writer.Write
	r.ArchiveDiscovery = ch.WriteDiscoveryEvidenceArchive
	event := recoveryFixtureEvent(prefix, prefix+"-product")
	event.Payload["product_model"] = "DS-2CD2143G0-I"
	rawHash := discoveryRawHash(event)
	if err = r.AcceptDiscoveryBatch(ctx, prefix+"-original", []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ProcessDiscoveryBatch(ctx); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = pg.db.QueryRowContext(ctx, `SELECT content_hash FROM discovery_event_receipts WHERE sensor_id=$1`, prefix).Scan(&hash); err != nil || hash != rawHash {
		t.Fatalf("raw receipt changed: %v", err)
	}
	derived, err := discovery.FromEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := discoveryRawHash(derived.Evidence)
	if legacyHash == rawHash {
		t.Fatal("fixture does not exercise product enrichment")
	}
	if _, err = pg.db.ExecContext(ctx, `UPDATE discovery_event_receipts SET content_hash=$2 WHERE sensor_id=$1`, prefix, legacyHash); err != nil {
		t.Fatal(err)
	}
	// A mixed batch hydrates the verified legacy receipt and publishes only new work.
	fresh := recoveryFixtureEvent(prefix, prefix+"-fresh")
	if err = writer.Write(ctx, []normalized.Event{event, fresh}); err != nil {
		t.Fatal(err)
	}
	if err = r.AcceptDiscoveryBatch(ctx, prefix+"-duplicate", []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ProcessDiscoveryBatch(ctx); err != nil {
		t.Fatal(err)
	}
	forged := event
	forged.Payload = map[string]any{}
	for key, value := range event.Payload {
		forged.Payload[key] = value
	}
	forged.Payload["product_verified"] = false
	if err = writer.Write(ctx, []normalized.Event{forged}); !errors.Is(err, discovery.ErrDiscoveryContentConflict) {
		t.Fatalf("forged original admitted: %v", err)
	}
}
