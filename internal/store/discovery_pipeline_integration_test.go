package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"sync"
	"testing"
	"time"
)

func TestDiscoveryDurablePipelineRecoveryAndLifecycle(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	prefix := "iot-replay-" + time.Now().UTC().Format("150405.000000000")
	now := time.Now().UTC().Add(-time.Second)
	event := normalized.Event{SchemaVersion: "v1", EventID: prefix + "-camera", Source: "passive", SourceEventType: "ws_discovery", Type: "discovery", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": prefix, "source_id": prefix, "interface": "mirror0"}, Subject: map[string]any{"site": "test", "domain": "test", "vlan": "12", "ip": "10.11.12.13"}, Payload: map[string]any{"origin": "ws_discovery", "is_response": true, "endpoint_reference": "camera-uuid", "types": "dn:NetworkVideoTransmitter", "ttl": 3600}}
	fail := true
	calls := 0
	repo := discovery.Repository{DB: pg.db, PipelineV2: true, Archive: func(context.Context, []normalized.Event) error {
		calls++
		if fail {
			return fmt.Errorf("simulated archive failure")
		}
		return nil
	}}
	if err = repo.AcceptDiscoveryBatch(ctx, prefix, []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	if worked, e := repo.ProcessDiscoveryBatch(ctx); !worked || e == nil {
		t.Fatalf("archive failure not exposed %v %v", worked, e)
	}
	var completed bool
	if e := pg.db.QueryRowContext(ctx, `SELECT completed FROM discovery_batch_work WHERE batch_id=$1`, prefix).Scan(&completed); e != nil || completed {
		t.Fatalf("failed batch completed %v %v", completed, e)
	}
	fail = false
	_, _ = pg.db.ExecContext(ctx, `UPDATE discovery_batch_work SET next_attempt_at=now() WHERE batch_id=$1`, prefix)
	if _, err = repo.ProcessDiscoveryBatch(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := repo.DevicesState(ctx, discovery.DeviceQuery{View: "iot", Search: "10.11.12.13", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]map[string]any)
	if len(items) != 1 || items[0]["device_type"] != "camera" {
		t.Fatalf("camera missing %+v", page)
	}
	id := items[0]["id"].(string)
	// A cross-batch retry must not append history or increment device version.
	version := items[0]["result_version"]
	if err = repo.AcceptDiscoveryBatch(ctx, prefix+"-duplicate", []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ProcessDiscoveryBatch(ctx); err != nil {
		t.Fatal(err)
	}
	page, err = repo.DevicesState(ctx, discovery.DeviceQuery{View: "iot", Search: "10.11.12.13", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if page["items"].([]map[string]any)[0]["result_version"] != version {
		t.Fatal("duplicate rewrote device")
	}
	// Same batch ID with different content must be rejected before exporting.
	changed := event
	changed.EventID += "-changed"
	if err = repo.AcceptDiscoveryBatch(ctx, prefix, []normalized.Event{changed}); err == nil {
		t.Fatal("conflicting batch accepted")
	}
	// Natural expiration updates the current classification but retains the file.
	_, err = pg.db.ExecContext(ctx, `UPDATE discovery_service_facts_v2 SET valid_until=now()-interval '1 second',observation=jsonb_set(observation,'{valid_until}',to_jsonb(now()-interval '1 second')) WHERE device_key=$1;`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pg.db.ExecContext(ctx, `UPDATE discovery_device_state_v2 SET expires_at=now()-interval '1 second' WHERE device_key=$1`, id)
	if err = repo.ExpireDiscoveryStates(ctx); err != nil {
		t.Fatal(err)
	}
	page, err = repo.DevicesState(ctx, discovery.DeviceQuery{View: "iot", Search: "10.11.12.13", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if rows := page["items"].([]map[string]any); len(rows) != 1 || rows[0]["classification_status"] != "expired" {
		t.Fatalf("expired archive disappeared: %+v", page)
	}
	if calls != 3 {
		t.Fatalf("unexpected archive attempts %d", calls)
	}
	// Unrelated service withdrawal cannot retract an expired camera conclusion.
	other := event
	other.EventID = prefix + "-unrelated"
	other.SourceEventType = "ssdp"
	other.Payload = map[string]any{"origin": "ssdp", "usn": "unrelated", "ttl": 0, "withdrawn": true}
	other.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	if e := repo.AcceptDiscoveryBatch(ctx, prefix+"-unrelated", []normalized.Event{other}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.ProcessDiscoveryBatch(ctx); e != nil {
		t.Fatal(e)
	}
	page, err = repo.DevicesState(ctx, discovery.DeviceQuery{View: "iot", Search: "10.11.12.13"})
	if err != nil || len(page["items"].([]map[string]any)) != 1 {
		t.Fatalf("unrelated withdrawal removed camera %v %v", page, err)
	}
	// A higher revision retracts the same fact even with an older occurrence time.
	corrected := event
	corrected.Timestamp = now.Add(-time.Minute).Format(time.RFC3339Nano)
	corrected.Payload = map[string]any{"origin": "ws_discovery", "is_response": true, "endpoint_reference": "camera-uuid", "ttl": 0, "withdrawn": true, "revision": 1}
	if e := repo.AcceptDiscoveryBatch(ctx, prefix+"-correction", []normalized.Event{corrected}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.ProcessDiscoveryBatch(ctx); e != nil {
		t.Fatal(e)
	}
	page, err = repo.DevicesState(ctx, discovery.DeviceQuery{View: "iot", Search: "10.11.12.13"})
	if err != nil || len(page["items"].([]map[string]any)) != 0 {
		t.Fatalf("correction retained camera %v %v", page, err)
	}
	// The same IP in another VLAN remains a separate scope.
	scoped := event
	scoped.EventID = prefix + "-vlan"
	scoped.Payload = map[string]any{"origin": "ws_discovery", "is_response": true, "endpoint_reference": "camera-uuid", "types": "dn:NetworkVideoTransmitter", "xaddrs": "http://10.11.12.13/onvif/device_service", "ttl": 3600}
	scoped.Subject = map[string]any{"site": "test", "domain": "test", "vlan": "13", "ip": "10.11.12.13"}
	scoped.Timestamp = time.Now().UTC().Add(-time.Millisecond).Format(time.RFC3339Nano)
	if e := repo.AcceptDiscoveryBatch(ctx, prefix+"-vlan", []normalized.Event{scoped}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.ProcessDiscoveryBatch(ctx); e != nil {
		t.Fatal(e)
	}
	page, err = repo.DevicesState(ctx, discovery.DeviceQuery{View: "iot", Search: "10.11.12.13", VLAN: "13"})
	if err != nil || len(page["items"].([]map[string]any)) != 1 {
		t.Fatalf("VLAN separation failed %v %v", page, err)
	}
	history, e := repo.DiscoveryHistory(ctx, id, "", 1)
	if e != nil {
		t.Fatal(e)
	}
	cursor := history["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("history cursor missing")
	}
	if _, e = repo.DiscoveryHistory(ctx, "different-device", cursor, 1); e == nil {
		t.Fatal("cross-device history cursor accepted")
	}
	if e = repo.UpdateDiscoveryStatistics(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.DiscoveryStatistics(ctx); e != nil {
		t.Fatal(e)
	}
	// Unverified enrichment remains a durable blocked task and performs no HTTP call.
	worker := discovery.EnrichmentWorker{Repository: repo, Fetch: func(context.Context, string, string, []byte) ([]byte, error) {
		t.Fatal("unverified target contacted")
		return nil, nil
	}}
	if _, e = worker.Step(ctx); e == nil {
		t.Fatal("blocked enrichment not exposed")
	}
	var reason string
	if e = pg.db.QueryRowContext(ctx, `SELECT error FROM discovery_enrichment_work WHERE error<>'' LIMIT 1`).Scan(&reason); e != nil || reason != "scope_path_unverified" {
		t.Fatalf("blocked task missing %q %v", reason, e)
	}

	// A large committed file batch is archived in bounded stable slices. A failed
	// slice retains its offset and the same archive key on retry.
	segmentEvents := make([]normalized.Event, 121)
	for i := range segmentEvents {
		segmentEvents[i] = event
		segmentEvents[i].EventID = fmt.Sprintf("%s-segment-%03d", prefix, i)
	}
	archiveKeys := []string{}
	failSegment := false
	repo.ArchiveDiscovery = func(_ context.Context, key string, _ time.Time, part []normalized.Event) error {
		if len(part) > 50 {
			t.Fatalf("unbounded archive slice: %d", len(part))
		}
		archiveKeys = append(archiveKeys, key)
		if failSegment {
			return fmt.Errorf("interrupted archive slice")
		}
		return nil
	}
	segmentedID := prefix + "-segments"
	if err = repo.AcceptDiscoveryBatch(ctx, segmentedID, segmentEvents); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ProcessDiscoveryBatch(ctx); err != nil {
		t.Fatal(err)
	}
	failSegment = true
	if _, err = repo.ProcessDiscoveryBatch(ctx); err == nil {
		t.Fatal("archive interruption ignored")
	}
	var progress int
	if err = pg.db.QueryRowContext(ctx, `SELECT processed_offset,completed FROM discovery_batch_work WHERE batch_id=$1`, segmentedID).Scan(&progress, &completed); err != nil || progress != 50 || completed {
		t.Fatalf("lost partial progress %d %v %v", progress, completed, err)
	}
	failSegment = false
	if _, err = pg.db.ExecContext(ctx, `UPDATE discovery_batch_work SET next_attempt_at=now() WHERE batch_id=$1`, segmentedID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = repo.ProcessDiscoveryBatch(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(archiveKeys) != 4 || archiveKeys[1] != archiveKeys[2] {
		t.Fatalf("unstable archive retry: %v", archiveKeys)
	}
	if err = pg.db.QueryRowContext(ctx, `SELECT processed_offset,completed FROM discovery_batch_work WHERE batch_id=$1`, segmentedID).Scan(&progress, &completed); err != nil || progress != 121 || !completed {
		t.Fatalf("incomplete batch %d %v %v", progress, completed, err)
	}
	fresh, err := repo.DiscoveryFreshness(ctx)
	if err != nil || fresh["status"] != "ready" || fresh["ingested_at"] == nil || fresh["processed_at"] == nil {
		t.Fatalf("watermark missing: %v %v", fresh, err)
	}

	// A parse-invalid first observation is durably receipted as rejected while
	// the valid record in the same captured file continues through projection.
	spool := t.TempDir()
	bad := event
	bad.EventID = prefix + "-invalid-address"
	bad.Subject = map[string]any{"ip": "224.0.0.1", "domain": "test"}
	good := scoped
	good.EventID = prefix + "-spool-valid"
	good.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	binaryText := event
	binaryText.EventID = prefix + "-binary-text"
	binaryText.Payload = map[string]any{"origin": "dns_sd", "is_response": true, "ttl": 120, "txt": []string{"model=Printer\x00firmware"}}
	raw, _ := json.Marshal([]normalized.Event{bad, binaryText, good})
	file := filepath.Join(spool, "invalid-first.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = repo.DrainSpool(ctx, spool); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("durable handoff failed: %v", err)
	}
	if _, err = repo.ProcessDiscoveryBatch(ctx); err != nil {
		t.Fatal(err)
	}
	var rejected, applied int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE result LIKE 'rejected:%'),count(*) FILTER(WHERE result='applied') FROM discovery_event_receipts WHERE batch_id='discovery:invalid-first'`).Scan(&rejected, &applied); err != nil || rejected != 2 || applied != 1 {
		t.Fatalf("spool receipts rejected=%d applied=%d err=%v", rejected, applied, err)
	}

	// Capture counters and disjoint device batches share protocol rows. Run
	// them together to catch reverse row-lock order and lost batch progress.
	repo.Archive = func(context.Context, []normalized.Event) error { return nil }
	repo.ArchiveDiscovery = func(context.Context, string, time.Time, []normalized.Event) error { return nil }
	concurrentCtx, concurrentCancel := context.WithTimeout(ctx, 20*time.Second)
	defer concurrentCancel()
	for i := 0; i < 20; i++ {
		firstEvent := event
		firstEvent.EventID = fmt.Sprintf("%s-concurrent-%d", prefix, i)
		firstEvent.Subject = map[string]any{"ip": fmt.Sprintf("10.20.0.%d", i+1), "domain": "concurrent"}
		secondEvent := firstEvent
		secondEvent.EventID += "-ssdp"
		secondEvent.SourceEventType = "ssdp"
		secondEvent.Payload = map[string]any{"origin": "ssdp", "is_response": true, "usn": fmt.Sprint(i), "ttl": 120}
		if e := repo.AcceptDiscoveryBatch(concurrentCtx, fmt.Sprintf("%s-concurrent-%d", prefix, i), []normalized.Event{firstEvent, secondEvent}); e != nil {
			t.Fatal(e)
		}
	}
	stats := discovery.NewCaptureStats()
	stats.Config = discovery.DefaultCollectionConfig()
	stats.UpdatedAt = time.Now().UTC()
	statsRaw, _ := json.Marshal(stats)
	if e := os.WriteFile(filepath.Join(spool, "capture.stats"), statsRaw, 0600); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 3)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, e := repo.ProcessDiscoveryBatch(concurrentCtx); e != nil {
					failures <- e
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			if e := repo.UpdateCaptureRuntime(concurrentCtx, spool, prefix); e != nil {
				failures <- e
				return
			}
		}
	}()
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	var remaining int
	if e := pg.db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_batch_work WHERE NOT completed`).Scan(&remaining); e != nil || remaining != 0 {
		t.Fatalf("concurrent tasks incomplete: %d %v", remaining, e)
	}

}
