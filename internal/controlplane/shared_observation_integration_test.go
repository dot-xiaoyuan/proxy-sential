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
	defer db.ExecContext(context.Background(), `DELETE FROM shared_observation_executions WHERE account_id=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM shared_behavior_observations WHERE sensor_id=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM shared_observation_jobs WHERE sensor_id=$1`, sensor)
	mapping := sharedaccess.IdentityMapping{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", Source: sensor, IdentitySensorID: sensor + "-auth", IdentityCampusID: "lab", IdentityAccessDomain: "auth", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	cfg := sharedaccess.Config{Version: "isolated-v1", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", Source: "handshake-sidecar"}}, IdentityMappings: []sharedaccess.IdentityMapping{mapping}}
	samples := []sharedaccess.HandshakeSample{}
	for model, ua := range []string{"Mozilla/5.0 (Linux; Android 14; SM-S9280 Build/TEST)", "Mozilla/5.0 (Linux; Android 14; V2241A Build/TEST)"} {
		for i := 0; i < 3; i++ {
			at := now.Add(time.Duration(-20+i*5) * time.Second)
			samples = append(samples, sharedaccess.HandshakeSample{Family: "user_agent", Value: ua, EventID: fmt.Sprintf("ua-%d-%d", model, i), ObservedAt: at, Bucket: at.Unix() / 5}, sharedaccess.HandshakeSample{Family: "ja3", Value: strings.Repeat(fmt.Sprint(model+1), 32), EventID: fmt.Sprintf("tls-%d-%d", model, i), ObservedAt: at, Bucket: at.Unix() / 5})
		}
	}
	event := normalized.Event{SchemaVersion: "v1", EventID: sensor + "-summary", Type: "device", Source: "handshake-sidecar", SourceEventType: "handshake", Timestamp: now.Add(-30 * time.Second).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "collector_instance_id": "isolated"}, Subject: map[string]any{"ip": ip, "campus_id": "lab"}, Payload: map[string]any{"access_domain": "mirror", "handshake_schema": "handshake-samples/v1", "feature_samples": samples, "capture_coverage": sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: now.Add(-30 * time.Second), To: now, KernelStatsKnown: true}}}
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
	tables := []string{"enforcement_actions", "notification_outbox", "notification_delivery_attempts", "behavior_report_outbox", "control_plane_tasks"}
	before := map[string]int{}
	for _, table := range tables {
		var n int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		before[table] = n
	}
	s := &Server{operations: &operationsState{db: db}, reader: backend, readOnly: true, sharedConfig: cfg, sharedObservationEnabled: true, identitySources: []identitySourceRegistration{{IdentityScope: snapshot.IdentityScope, IntervalSeconds: 1800}}}
	for attempt := 0; attempt < 2; attempt++ {
		if err = backend.WriteNormalizedEvents(ctx, []normalized.Event{event}); err != nil {
			t.Fatal(err)
		}
		did, e := s.processSharedObservation(ctx, now)
		if e != nil || !did {
			t.Fatalf("process: %v %v", did, e)
		}
	}
	var n int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM policy_decision_records WHERE account_id=$1 AND result='matched' AND document->>'mode'='observe' AND document->>'delivery_status'='not_sent'`, sensor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one hit: %d %v", n, err)
	}
	for _, table := range tables {
		var n int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != before[table] {
			t.Fatalf("side effect in %s: before=%d after=%d err=%v", table, before[table], n, err)
		}
	}
}
