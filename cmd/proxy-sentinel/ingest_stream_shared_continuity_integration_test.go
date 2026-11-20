package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

func TestSharedPacketContinuityOnMigratedStores(t *testing.T) {
	postgresDSN := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	clickhouseDSN := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if postgresDSN == "" || clickhouseDSN == "" {
		t.Skip("isolated PostgreSQL and ClickHouse are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := sql.Open("pgx", postgresDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ch, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: clickhouseDSN, RequestTimeout: 8 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	prefix := fmt.Sprintf("continuity-%d", now.UnixMicro())
	packet, handshake := "/"+prefix+"/ttl.jsonl", "/"+prefix+"/handshake.jsonl"
	old, fresh, unchanged := prefix+"-old", prefix+"-fresh", prefix+"-handshake"
	scope, generation, manifest := prefix+"-scope", prefix+"-generation", strings.Repeat("a", 64)
	cutoff := now.Add(-8 * time.Minute)
	for _, item := range []struct{ epoch, path, state string }{{old, packet, "closed"}, {fresh, packet, "active"}, {unchanged, handshake, "active"}} {
		start := cutoff.Add(-time.Hour)
		if item.epoch == fresh {
			start = cutoff
		}
		exec(`INSERT INTO stream_source_cutovers(epoch,source_kind,source_path,sensor_id,file_id,start_offset,parser_version,
 previous_release,legacy_cutoff_at,legacy_cancel_id,state,cancel_manifest_sha256,capture_scope_sha256)
 VALUES($1,'device-signals',$2,$3,$2||':1:2',100,'device-v1','test',$4,$5,$6,$7,$7)`, item.epoch, item.path, prefix, start, generation, item.state, manifest)
	}
	for _, item := range []struct{ epoch, path, owner string }{{old, packet, "packet-sidecar"}, {unchanged, handshake, "handshake-sidecar"}} {
		exec(`INSERT INTO stream_shared_source_cutovers(sensor_id,source_owner,epoch,source_path,scope_id,source_cutoff_at,cancel_id,canceled_jobs,canceled_manifest_sha256,state)
 VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,'active')`, prefix, item.owner, item.epoch, item.path, scope, cutoff.Add(-time.Hour), generation, manifest)
	}
	if err := store.VerifyRequiredSharedStream(ctx, db, prefix, scope, "packet-sidecar", packet, fresh); !errors.Is(err, store.ErrSharedStreamBinding) {
		t.Fatalf("misbound packet accepted: %v", err)
	}
	packetSegment := func(eventID string, when time.Time, offset int64) streamlog.Segment {
		return streamlog.Segment{Epoch: fresh, Source: "device-signals", SourcePath: packet, FileID: packet + ":1:2",
			StartOffset: offset, EndOffset: offset + 1, ParserVersion: "device-v1", RawSHA256: manifest, RawIsStandardEvents: true,
			AcceptedAt: when, ArchiveMonth: when.Format("200601"), BodyLayout: "v2", Events: []normalized.Event{{
				SchemaVersion: "v1", EventID: eventID, Source: "packet-sidecar", SourceEventType: "ieee1905_client_association", Type: "device",
				Timestamp: when.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": prefix, "capture_scope_id": scope, "collector_instance_id": "collector"},
				Subject: map[string]any{"campus_id": "campus", "mac": "02:00:00:00:00:01"}, Payload: map[string]any{"access_domain": "campus"},
			}}}
	}
	currentSegment := packetSegment("current", now.Add(-time.Minute), 101)
	oldSegment := packetSegment("expired-0", now.Add(-6*time.Minute), 100)
	for i := 1; i < 17; i++ {
		duplicate := oldSegment.Events[0]
		duplicate.EventID = fmt.Sprintf("expired-%d", i)
		oldSegment.Events = append(oldSegment.Events, duplicate)
	}
	for _, segment := range []streamlog.Segment{oldSegment, currentSegment} {
		id := streamlog.SourceSegmentID(segment)
		if err := ch.WriteStreamBody(ctx, id, segment); err != nil {
			t.Fatal(err)
		}
		if err := ch.WriteStreamSearch(ctx, id, segment); err != nil {
			t.Fatal(err)
		}
	}
	input := sharedStreamRebind{Sensor: prefix, Scope: scope, ScopeHash: manifest, Owner: "packet-sidecar", Path: packet,
		OldEpoch: old, Epoch: fresh, Manifest: manifest, FileManifest: manifest, Cutoff: cutoff}
	for range 2 {
		if err := rebindStreamSharedSource(ctx, db, input); err != nil {
			t.Fatal(err)
		}
	}
	for owner, data := range map[string][2]string{"packet-sidecar": {packet, fresh}, "handshake-sidecar": {handshake, unchanged}} {
		if err := store.VerifyRequiredSharedStream(ctx, db, prefix, scope, owner, data[0], data[1]); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = store.LockSharedStreamEpochs(ctx, tx, prefix, generation, map[string]string{"packet-sidecar": old, "handshake-sidecar": unchanged})
	_ = tx.Rollback()
	if !errors.Is(err, store.ErrSharedStreamBinding) {
		t.Fatalf("in-flight old epoch accepted: %v", err)
	}
	queue := store.StreamSharedJobQueue{DB: db, RequiredSources: map[string]string{packet: "packet-sidecar"}}
	page, err := queue.RepairSharedPacketPage(ctx, ch, prefix, scope, packet, fresh, 180*time.Second)
	if err != nil || page.Complete || page.Examined != 16 {
		t.Fatalf("repair page %+v: %v", page, err)
	}
	// Model a process that committed individual receipts and stopped before
	// the page cursor commit. The next process must verify the same page.
	exec(`DELETE FROM stream_shared_packet_repair_progress WHERE epoch=$1`, fresh)
	page, err = queue.RepairSharedPacketPage(ctx, ch, prefix, scope, packet, fresh, 180*time.Second)
	if err != nil || page.Complete || page.Examined != 16 {
		t.Fatalf("repair page after interruption %+v: %v", page, err)
	}
	page, err = queue.RepairSharedPacketPage(ctx, ch, prefix, scope, packet, fresh, 180*time.Second)
	if err != nil || !page.Complete || page.Examined != 2 {
		t.Fatalf("repair page after cursor resume %+v: %v", page, err)
	}
	page, err = queue.RepairSharedPacketPage(ctx, ch, prefix, scope, packet, fresh, 180*time.Second)
	if err != nil || !page.Complete || page.Examined != 0 {
		t.Fatalf("repeated repair %+v: %v", page, err)
	}
	if err := queue.MarkStreamSharedJobs(ctx, streamlog.SourceSegmentID(currentSegment), currentSegment); err != nil {
		t.Fatal(err)
	}
	var revision int
	var received time.Time
	if err := db.QueryRowContext(ctx, `SELECT revision,first_received_at FROM shared_gateway_observation_jobs WHERE sensor_id=$1 AND source_epoch=$2`, prefix, fresh).Scan(&revision, &received); err != nil || revision != 1 || !received.Equal(currentSegment.AcceptedAt) {
		t.Fatalf("gateway revision=%d received=%s: %v", revision, received, err)
	}
	var expired int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM stream_shared_packet_repairs WHERE epoch=$1 AND state='expired_without_evaluation'`, fresh).Scan(&expired); err != nil || expired != 17 {
		t.Fatalf("expired history=%d: %v", expired, err)
	}
	const insertReceipt = `INSERT INTO stream_shared_segment_receipts(segment_id,epoch,source_path,source_owner,segment_sha256,event_count) VALUES($1,$2,$3,'packet-sidecar',$4,$5)`
	for _, size := range []int{1000, 1155, 2000} {
		exec(insertReceipt, fmt.Sprintf("%s-%d", prefix, size), fresh, packet, manifest, size)
	}
	_, err = db.ExecContext(ctx, insertReceipt, prefix+"-2001", fresh, packet, manifest, 2001)
	var constraintErr *pgconn.PgError
	if !errors.As(err, &constraintErr) || constraintErr.Code != "23514" {
		t.Fatalf("oversize receipt: %v", err)
	}
}
