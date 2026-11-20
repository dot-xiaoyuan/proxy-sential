package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in and isolated DSNs are required. This never starts a database.
func TestSharedObservationIsolatedEndToEnd(t *testing.T) {
	pgDSN, chDSN := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if os.Getenv("PROXY_SENTINEL_SHARED_TEST_ISOLATED") != "true" || pgDSN == "" || chDSN == "" {
		t.Skip("isolated PostgreSQL + ClickHouse and explicit shared-test opt-in required")
	}
	for _, dsn := range []string{pgDSN, chDSN} {
		u, err := url.Parse(dsn)
		if err != nil || u.Hostname() == "" {
			t.Fatal("isolated DSNs must be URLs")
		}
		if strings.Contains(dsn, "222.204.3.184") || strings.Contains(dsn, "192.168.0.30") {
			t.Fatal("field hosts are forbidden for replay")
		}
	}
	t.Setenv("PROXY_SENTINEL_SHARED_OBSERVATION_ENABLED", "true")
	t.Setenv("PROXY_SENTINEL_STREAM_SHARED_REQUIRED", "true")
	priorBypass := legacyTransportTestBypass.Swap(false)
	t.Cleanup(func() { legacyTransportTestBypass.Store(priorBypass) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, pgDSN, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyClickHouseMigrations(ctx, chDSN, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	backend, err := store.NewDBStore(store.Options{PostgresDSN: pgDSN, ClickHouseDSN: chDSN})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	db, err := sql.Open("pgx", pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sensor := fmt.Sprintf("shared-replay-%d", time.Now().UnixNano())
	ip := "192.0.2.44"
	now := time.Now().UTC().Truncate(time.Microsecond)
	defer db.ExecContext(context.Background(), `DELETE FROM policy_decision_records WHERE document->'evidence'->>'sensor_id'=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_actions WHERE account_id=$1 AND mode='record_only'`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM behavior_report_outbox WHERE account_id=$1 AND status='recorded'`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM shared_observation_executions WHERE account_id=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM shared_behavior_observations WHERE sensor_id=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM shared_observation_jobs WHERE sensor_id=$1`, sensor)
	mapping := sharedaccess.IdentityMapping{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", Source: sensor, IdentitySensorID: sensor + "-auth", IdentityCampusID: "lab", IdentityAccessDomain: "auth", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	cfg := sharedaccess.Config{Version: "isolated-v1", FreshnessSeconds: 180, Sources: []sharedaccess.Source{
		{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", Source: "handshake-sidecar"},
		{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", Source: "packet-sidecar"},
	}, IdentityMappings: []sharedaccess.IdentityMapping{mapping}}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	packetPath, handshakePath := "/"+sensor+"/ttl.jsonl", "/"+sensor+"/handshake.jsonl"
	packetEpoch, handshakeEpoch, generation := sensor+"-packet", sensor+"-handshake", sensor+"-generation"
	scopeID, proof := sensor+"-scope", strings.Repeat("a", 64)
	exec(`INSERT INTO behavior_report_channels(channel_id,name,enabled) VALUES($1,$1,true)`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM behavior_report_channels WHERE channel_id=$1`, sensor)
	for _, source := range []struct{ path, epoch, owner string }{{packetPath, packetEpoch, "packet-sidecar"}, {handshakePath, handshakeEpoch, "handshake-sidecar"}} {
		exec(`INSERT INTO stream_source_cutovers(epoch,source_kind,source_path,sensor_id,file_id,start_offset,parser_version,previous_release,legacy_cutoff_at,legacy_cancel_id,state,cancel_manifest_sha256,capture_scope_sha256)
 VALUES($1,'device-signals',$2,$3,$2||':1:2',0,'device-v1','test',$4,$5,'active',$6,$6)`, source.epoch, source.path, sensor, now.Add(-time.Hour), generation, proof)
		exec(`INSERT INTO stream_shared_source_cutovers(sensor_id,source_owner,epoch,source_path,scope_id,source_cutoff_at,cancel_id,canceled_jobs,canceled_manifest_sha256,state)
 VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,'active')`, sensor, source.owner, source.epoch, source.path, scopeID, now.Add(-time.Hour), generation, proof)
	}
	gatewayMAC := "02:00:00:00:00:01"
	exec(`INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,observed_at,valid_until,action)
 VALUES($1,'lab',$1,$2,'mac:'||$3,$4,$5,'ack')`, sensor, ip, gatewayMAC, now.Add(-time.Minute), now.Add(time.Hour))
	event := normalized.Event{SchemaVersion: "v1", EventID: sensor + "-association", Type: "device", Source: "packet-sidecar", SourceEventType: "ieee1905_client_snapshot",
		Timestamp: now.Add(-30 * time.Second).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "collector_instance_id": "isolated", "capture_scope_id": scopeID},
		Subject: map[string]any{"mac": gatewayMAC, "campus_id": "lab"}, Payload: map[string]any{"access_domain": "mirror",
			"bss_snapshots":    []map[string]any{{"bssid": "02:00:00:00:00:02", "client_macs": []string{"02:00:00:00:00:03", "02:00:00:00:00:04"}}},
			"capture_coverage": sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: now.Add(-40 * time.Second), To: now, KernelStatsKnown: true}}}
	segment := streamlog.Segment{Epoch: packetEpoch, Source: "device-signals", SourcePath: packetPath, FileID: packetPath + ":1:2", EndOffset: 1,
		ParserVersion: "device-v1", AcceptedAt: now, ArchiveMonth: now.Format("200601"), RawIsStandardEvents: true, Events: []normalized.Event{event}}
	segmentID := streamlog.SourceSegmentID(segment)
	archive, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: chDSN, RequestTimeout: 8 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.WriteStreamBody(ctx, segmentID, segment); err != nil {
		t.Fatal(err)
	}
	if err := archive.WriteStreamSearch(ctx, segmentID, segment); err != nil {
		t.Fatal(err)
	}
	identity := normalized.Event{SchemaVersion: "v1", EventID: sensor + "-identity", Type: "identity", Source: sensor, Timestamp: now.Add(-time.Minute).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor + "-auth"}, Subject: map[string]any{"entity_role": "endpoint", "ip": ip, "account_id": sensor, "session_id": sensor, "campus_id": "lab"}, Payload: map[string]any{"origin": sensor, "session_id": sensor, "campus_id": "lab", "access_domain": "auth", "session_status": "reconcile", "heartbeat_interval_seconds": "1800"}}
	snapshot := store.IdentitySnapshot{IdentityScope: store.IdentityScope{Source: sensor, SensorID: sensor + "-auth", CampusID: "lab", AccessDomain: "auth"}, SnapshotID: sensor, ObservedAt: now.Add(-time.Minute), IntervalSeconds: 1800, Events: []normalized.Event{identity}}
	if _, err = backend.CommitIdentitySnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	// Shared observation reads membership from the snapshot projection, which is applied asynchronously.
	if err = backend.ProjectPendingIdentitySnapshots(ctx, 10); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM account_identity_session_projection WHERE source=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM account_identity_projection_sources WHERE source=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM identity_snapshot_log WHERE source=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM identity_full_snapshots WHERE source=$1`, sensor)
	tables := []string{"notification_outbox", "notification_delivery_attempts", "control_plane_tasks"}
	before := map[string]int{}
	for _, table := range tables {
		var n int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		before[table] = n
	}
	s := &Server{operations: &operationsState{db: db}, reader: backend, sensorID: sensor, readOnly: true, sharedConfig: cfg, sharedObservationEnabled: true, identitySources: []identitySourceRegistration{{IdentityScope: snapshot.IdentityScope, IntervalSeconds: 1800}}}
	exec(`INSERT INTO stream_shared_source_runtime(sensor_id,source_path,epoch,accepted_segment,accepted_at,archived_segment,archived_at)
 VALUES($1,$2,$3,$4,$5,$4,$5)`, sensor, packetPath, packetEpoch, segmentID, now)
	queue := store.StreamSharedJobQueue{DB: db, RequiredSources: map[string]string{packetPath: "packet-sidecar"}}
	for attempt := 0; attempt < 2; attempt++ {
		if err = queue.MarkStreamSharedJobs(ctx, segmentID, segment); err != nil {
			t.Fatal(err)
		}
		if did, e := backend.ResolveSharedGateway(ctx, cfg, now); e != nil || did != (attempt == 0) {
			t.Fatalf("gateway resolution: attempt=%d worked=%t error=%v", attempt, did, e)
		}
		did, e := s.processSharedObservation(ctx, now)
		if e != nil || did != (attempt == 0) {
			t.Fatalf("process: %v %v", did, e)
		}
	}
	var n int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM policy_decision_records WHERE account_id=$1 AND result='matched' AND document->>'mode'='manual' AND document->>'delivery_status'='record_only'`, sensor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one hit: %d %v", n, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM enforcement_actions WHERE account_id=$1 AND status='recorded' AND mode='record_only'`, sensor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one record-only action: %d %v", n, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM behavior_report_outbox WHERE account_id=$1 AND channel_id=$1
 AND status='recorded' AND payload->>'external_request_sent'='false'`, sensor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one record-only report: %d %v", n, err)
	}
	progress, err := s.readSharedStreamProgress(ctx, time.Now())
	if err != nil || len(progress) != 2 {
		t.Fatalf("shared source progress: %+v %v", progress, err)
	}
	for _, source := range progress {
		if source.Owner == "packet-sidecar" && (source.State != "healthy" || source.AcceptedSegment != segmentID || source.SharedConfirmedSegment != segmentID) {
			t.Fatalf("packet status does not match durable work: %+v", source)
		}
	}
	for _, table := range tables {
		var n int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != before[table] {
			t.Fatalf("side effect in %s: before=%d after=%d err=%v", table, before[table], n, err)
		}
	}
}
