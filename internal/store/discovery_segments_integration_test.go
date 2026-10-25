package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

// This test uses an isolated PostgreSQL database with migration 172 applied.
// It never runs against the field database or creates a local container.
func TestDiscoverySegmentsPostgresArchiveAndRelease(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var exists bool
	if err = pg.db.QueryRowContext(ctx, `SELECT to_regclass('discovery_batch_segments') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Skip("migration 172 required")
	}
	sensor := fmt.Sprintf("segment-replay-%d", time.Now().UnixNano())
	batch := sensor + "-batch"
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		for _, statement := range []string{
			`DELETE FROM discovery_device_changes_v2 WHERE document->'evidence'->'observer'->>'sensor_id'=$1`,
			`DELETE FROM discovery_service_facts_v2 WHERE sensor_id=$1`,
			`DELETE FROM discovery_device_state_v2 WHERE sensor_id=$1`,
			`DELETE FROM discovery_event_receipts WHERE sensor_id=$1`,
			`DELETE FROM discovery_normalized_receipts WHERE sensor_id=$1`,
			`DELETE FROM discovery_protocol_runtime WHERE sensor_id=$1`,
		} {
			if _, cleanupErr := pg.db.ExecContext(cleanup, statement, sensor); cleanupErr != nil {
				t.Logf("cleanup %s: %v", statement, cleanupErr)
			}
		}
		for _, statement := range []string{
			`DELETE FROM discovery_batch_segments WHERE batch_id=$1`,
			`DELETE FROM discovery_batch_work WHERE batch_id=$1`,
			`DELETE FROM ingest_batches WHERE batch_id=$1`,
		} {
			if _, cleanupErr := pg.db.ExecContext(cleanup, statement, batch); cleanupErr != nil {
				t.Logf("cleanup %s: %v", statement, cleanupErr)
			}
		}
	}()
	events := make([]normalized.Event, 51)
	for i := range events {
		events[i] = recoveryFixtureEvent(sensor, fmt.Sprintf("%s-event-%02d", sensor, i))
		events[i].Subject["ip"] = fmt.Sprintf("10.91.0.%d", i+1)
	}
	r := discovery.Repository{DB: pg.db, ClaimSensor: sensor}
	if err = r.AcceptDiscoveryBatch(ctx, batch, events); err != nil {
		t.Fatal(err)
	}
	// Recreate the 50+1 layout emitted before smaller publication slices were
	// introduced. Existing admitted segments must remain readable unchanged.
	if _, err = pg.db.ExecContext(ctx, `DELETE FROM discovery_batch_segments WHERE batch_id=$1`, batch); err != nil {
		t.Fatal(err)
	}
	for _, start := range []int{0, 50} {
		end := min(start+50, len(events))
		raw, encodeErr := discovery.EncodeDiscoveryBatch(events[start:end])
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if _, err = pg.db.ExecContext(ctx, `INSERT INTO discovery_batch_segments(batch_id,first_offset,event_count,byte_count,content_sha256,events) VALUES($1,$2,$3,$4,$5,$6)`, batch, start, end-start, len(raw), discovery.DiscoveryBatchHash(events[start:end]), raw); err != nil {
			t.Fatal(err)
		}
	}
	var segments, selected int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*),max(w.selected_event_count) FROM discovery_batch_segments s JOIN discovery_batch_work w USING(batch_id) WHERE s.batch_id=$1`, batch).Scan(&segments, &selected); err != nil || segments != 2 || selected != 51 {
		t.Fatalf("segments=%d selected=%d: %v", segments, selected, err)
	}
	archiveSizes := []int{}
	r.Archive = func(_ context.Context, input []normalized.Event) error {
		archiveSizes = append(archiveSizes, len(input))
		return nil
	}
	r.ArchiveDiscovery = func(context.Context, string, time.Time, []normalized.Event) error {
		return errors.New("partial archive")
	}
	if _, err = r.ProcessDiscoveryBatch(ctx); err == nil {
		t.Fatal("archive failure advanced task")
	}
	var offset int
	var retained bool
	var archiveMarked bool
	if err = pg.db.QueryRowContext(ctx, `SELECT w.processed_offset,s.events IS NOT NULL,s.archive_verified_at IS NOT NULL FROM discovery_batch_work w JOIN discovery_batch_segments s USING(batch_id) WHERE w.batch_id=$1 AND s.first_offset=0`, batch).Scan(&offset, &retained, &archiveMarked); err != nil || offset != 0 || !retained || archiveMarked {
		t.Fatalf("partial archive lost original: offset=%d retained=%v err=%v", offset, retained, err)
	}
	if _, err = pg.db.ExecContext(ctx, `UPDATE discovery_batch_work SET next_attempt_at=now(),lease_until='-infinity' WHERE batch_id=$1`, batch); err != nil {
		t.Fatal(err)
	}
	archiveSizes = nil
	var ch *ClickHouseStore
	archiveCalls := 0
	if chDSN := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN"); chDSN != "" {
		if _, err = ApplyClickHouseMigrations(ctx, chDSN, "../../migrations/clickhouse"); err != nil {
			t.Fatal(err)
		}
		ch, err = NewClickHouseStore(ClickHouseOptions{DSN: chDSN})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if cleanupErr := ch.exec(context.Background(), "ALTER TABLE normalized_events DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=1"); cleanupErr != nil {
				t.Logf("normalized cleanup: %v", cleanupErr)
			}
			if cleanupErr := ch.exec(context.Background(), "ALTER TABLE discovery_evidence_archive DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=1"); cleanupErr != nil {
				t.Logf("archive cleanup: %v", cleanupErr)
			}
		}()
		writer := NewDiscoveryArchiveWriter(pg.db, ch)
		r.Archive = func(c context.Context, input []normalized.Event) error {
			archiveSizes = append(archiveSizes, len(input))
			return writer.Write(c, input)
		}
		r.ArchiveDiscovery = func(c context.Context, id string, at time.Time, input []normalized.Event) error {
			archiveCalls++
			return ch.WriteDiscoveryEvidenceArchive(c, id, at, input)
		}
	} else {
		r.ArchiveDiscovery = func(context.Context, string, time.Time, []normalized.Event) error { archiveCalls++; return nil }
	}
	for i, wantOffset := range []int{10, 20, 30, 40, 50, 51} {
		started := time.Now()
		worked, processErr := r.ProcessDiscoveryBatch(ctx)
		t.Logf("segment %d publication duration: %s", i, time.Since(started))
		if processErr != nil || !worked {
			t.Fatalf("segment %d: worked=%v err=%v", i, worked, processErr)
		}
		if err = pg.db.QueryRowContext(ctx, `SELECT processed_offset FROM discovery_batch_work WHERE batch_id=$1`, batch).Scan(&offset); err != nil || offset != wantOffset {
			t.Fatalf("slice %d offset=%d want=%d err=%v", i, offset, wantOffset, err)
		}
	}
	if archiveCalls != 2 {
		t.Fatalf("full segment archive repeated: %d", archiveCalls)
	}
	if len(archiveSizes) != 6 || archiveSizes[0] != 10 || archiveSizes[1] != 10 || archiveSizes[2] != 10 || archiveSizes[3] != 10 || archiveSizes[4] != 10 || archiveSizes[5] != 1 {
		t.Fatalf("normalized archive was not bounded per publication: %v", archiveSizes)
	}
	var released, receipts int
	var completed bool
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE events IS NULL AND archive_verified_at IS NOT NULL AND released_at IS NOT NULL) FROM discovery_batch_segments WHERE batch_id=$1`, batch).Scan(&released); err != nil || released != 2 {
		t.Fatalf("released=%d: %v", released, err)
	}
	if err = pg.db.QueryRowContext(ctx, `SELECT completed,processed_offset FROM discovery_batch_work WHERE batch_id=$1`, batch).Scan(&completed, &offset); err != nil || !completed || offset != 51 {
		t.Fatalf("completed=%v offset=%d: %v", completed, offset, err)
	}
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_event_receipts WHERE sensor_id=$1`, sensor).Scan(&receipts); err != nil || receipts != 51 {
		t.Fatalf("receipts=%d: %v", receipts, err)
	}
	var archiveBatch string
	var archiveOrdinal int
	if err = pg.db.QueryRowContext(ctx, `SELECT archive_batch_id,archive_ordinal FROM discovery_event_receipts WHERE sensor_id=$1 AND event_id=$2`, sensor, events[35].EventID).Scan(&archiveBatch, &archiveOrdinal); err != nil || archiveBatch != batch+"/segment/0" || archiveOrdinal != 35 {
		t.Fatalf("partial archive locator=%q/%d err=%v", archiveBatch, archiveOrdinal, err)
	}
	if ch != nil {
		ref := DiscoveryCaseEvidenceRef{SensorID: sensor, SourceID: sensor, EventID: events[0].EventID, Revision: 0}
		originals, readErr := (&DBStore{pg: pg, ch: ch}).ReadDiscoveryCaseEvidence(ctx, []DiscoveryCaseEvidenceRef{ref})
		if readErr != nil {
			t.Fatal(readErr)
		}
		var original normalized.Event
		if readErr = json.Unmarshal(originals[ref].Document, &original); readErr != nil || original.EventID != ref.EventID {
			t.Fatalf("case original unavailable: event=%s err=%v", original.EventID, readErr)
		}
	}
}
