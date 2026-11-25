package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
	"slices"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in and isolated DSNs are required. This never starts a database.
func TestSharedObservationIsolatedEndToEnd(t *testing.T) {
	for _, basis := range []string{"ieee1905_association", sharedaccess.AuthenticatedRouter} {
		t.Run(basis, func(t *testing.T) { runSharedObservationReplay(t, basis, "matched") })
	}
}

func TestSharedObservationIsolatedWhitelist(t *testing.T) {
	runSharedObservationReplay(t, sharedaccess.AuthenticatedRouter, "whitelist_suppressed")
}

func TestSharedObservationIsolatedRegisteredInfrastructure(t *testing.T) {
	runSharedObservationReplay(t, sharedaccess.AuthenticatedRouter, "infrastructure_ownership")
}

func runSharedObservationReplay(t *testing.T, basis, outcome string) {
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
	defer db.ExecContext(context.Background(), `DELETE FROM shared_gateway_observation_jobs WHERE sensor_id=$1`, sensor)
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
	if outcome == "whitelist_suppressed" {
		expires := now.Add(time.Hour)
		manager := newWhitelistManager(db, "")
		entry, e := manager.save(ctx, policy.WhitelistEntry{Type: "username_contains", Value: strings.TrimPrefix(sensor, "shared-"), Reason: "教学共享回放", CampusID: "lab", Enabled: true, ValidFrom: now.Add(-time.Hour), ExpiresAt: &expires}, "", "create", "replay")
		if e != nil {
			t.Fatal(e)
		}
		defer manager.save(ctx, entry, entry.ID, "disable", "replay")
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
	event := normalized.Event{SchemaVersion: "v1", EventID: sensor + "-association", Type: "device", Source: "packet-sidecar", SourceEventType: "ieee1905_client_snapshot",
		Timestamp: now.Add(-30 * time.Second).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "collector_instance_id": "isolated", "capture_scope_id": scopeID},
		Subject: map[string]any{"mac": gatewayMAC, "campus_id": "lab"}, Payload: map[string]any{"access_domain": "mirror",
			"bss_snapshots":    []map[string]any{{"bssid": "02:00:00:00:00:02", "client_macs": []string{"02:00:00:00:00:03", "02:00:00:00:00:04"}}},
			"capture_coverage": sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: now.Add(-40 * time.Second), To: now, KernelStatsKnown: true}}}
	segment := streamlog.Segment{Epoch: packetEpoch, Source: "device-signals", SourcePath: packetPath, FileID: packetPath + ":1:2", EndOffset: 1,
		ParserVersion: "device-v1", AcceptedAt: now, ArchiveMonth: now.Format("200601"), RawIsStandardEvents: true, Events: []normalized.Event{event}}
	archive, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: chDSN, RequestTimeout: 8 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var roleRefs []store.StreamBodyRef
	var roleAssessment string
	path, epoch := packetPath, packetEpoch
	if basis == sharedaccess.AuthenticatedRouter {
		path, epoch = handshakePath, handshakeEpoch
		event.Source, event.SourceEventType, event.EventID = "handshake-sidecar", "handshake", sensor+"-syn"
		event.Subject["ip"] = ip
		event.Payload = map[string]any{"access_domain": "mirror", "mac": gatewayMAC, "handshake_schema": "handshake-samples/v1",
			"capture_coverage": sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: now.Add(-40 * time.Second), To: now},
			"outlet_activity":  sharedaccess.OutletActivity{MAC: gatewayMAC, EventID: "device-before-stream-rekey", At: now.Add(-30 * time.Second)}}
		segment.Epoch, segment.SourcePath, segment.FileID, segment.Events = epoch, path, path+":1:2", []normalized.Event{event}
		target := "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
		advert := normalized.Event{SchemaVersion: "v1", Type: "device", Source: "packet-sidecar", SourceEventType: "ssdp", EventID: sensor + "-igd",
			Timestamp: now.Add(-time.Minute).Format(time.RFC3339Nano), Observer: event.Observer,
			Subject: map[string]any{"entity_role": "network_device", "mac": gatewayMAC, "ip": ip, "campus_id": "lab"},
			Payload: map[string]any{"ssdp_advertisement": "alive", "nt": target, "usn": "uuid:" + sensor + "::" + target}}
		repeat := advert
		repeat.EventID += "-repeat"
		repeat.Timestamp = now.Add(-59 * time.Second).Format(time.RFC3339Nano)
		adverts := []normalized.Event{advert, repeat}
		roles, err := evidence.AnalyzeRouters(adverts, evidence.RouterOptions{AsOf: now})
		if err != nil || len(roles.Assessments) != 1 {
			t.Fatalf("analyze passive gateway: %v assessments=%d", err, len(roles.Assessments))
		}
		roleSegment := segment
		roleSegment.Epoch, roleSegment.SourcePath, roleSegment.FileID, roleSegment.Events = packetEpoch, packetPath, packetPath+":1:3", adverts
		roleSegmentID := streamlog.SourceSegmentID(roleSegment)
		if err := archive.WriteStreamBody(ctx, roleSegmentID, roleSegment); err != nil {
			t.Fatal(err)
		}
		if err := archive.WriteStreamSearch(ctx, roleSegmentID, roleSegment); err != nil {
			t.Fatal(err)
		}
		indexed, err := archive.ListStreamRouterSignalRefs(ctx, sensor, now.Add(-time.Minute), "", 10)
		if err != nil || len(indexed) != 2 {
			t.Fatalf("archive router original: found=%d err=%v", len(indexed), err)
		}
		roleRefs, roleAssessment = []store.StreamBodyRef{indexed[0].Body, indexed[1].Body}, roles.Assessments[0].AssessmentID
		// Simulate the pre-fix durable interpretation of this exact original.
		for i := range roles.Evidence {
			roles.Evidence[i].Infrastructure = true
		}
		defer db.ExecContext(context.Background(), `DELETE FROM router_assessments WHERE assessment_id=$1`, roles.Assessments[0].AssessmentID)
		if err := backend.WriteRouterObservations(ctx, roles); err != nil {
			t.Fatal(err)
		}
	} else {
		exec(`INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,observed_at,valid_until,action)
 VALUES($1,'lab',$1,$2,'mac:'||$3,$4,$5,'ack')`, sensor, ip, gatewayMAC, now.Add(-time.Minute), now.Add(time.Hour))
	}
	segmentID := streamlog.SourceSegmentID(segment)
	if err := archive.WriteStreamBody(ctx, segmentID, segment); err != nil {
		t.Fatal(err)
	}
	if err := archive.WriteStreamSearch(ctx, segmentID, segment); err != nil {
		t.Fatal(err)
	}
	identity := normalized.Event{SchemaVersion: "v1", EventID: sensor + "-identity", Type: "identity", Source: sensor, Timestamp: now.Add(-time.Minute).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor + "-auth"}, Subject: map[string]any{"entity_role": "endpoint", "ip": ip, "mac": gatewayMAC, "account_id": sensor, "session_id": sensor, "campus_id": "lab"}, Payload: map[string]any{"origin": sensor, "session_id": sensor, "campus_id": "lab", "access_domain": "auth", "session_status": "reconcile", "heartbeat_interval_seconds": "1800", "reconcile_interval_seconds": "1800"}}
	snapshot := store.IdentitySnapshot{IdentityScope: store.IdentityScope{Source: sensor, SensorID: sensor + "-auth", CampusID: "lab", AccessDomain: "auth"}, SnapshotID: sensor, ObservedAt: now.Add(-time.Minute), IntervalSeconds: 1800, Events: []normalized.Event{identity}}
	if _, err = backend.CommitIdentitySnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	// Shared observation reads membership from the snapshot projection, which is applied asynchronously.
	if err = backend.ProjectPendingIdentitySnapshots(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if basis == sharedaccess.AuthenticatedRouter {
		exec(`INSERT INTO shared_observation_mappings(config_version,sensor_id,campus_id,access_domain,identity_source,identity_sensor_id,identity_campus_id,identity_access_domain,valid_from,valid_until)
 VALUES($1,$2,'lab','mirror',$2,$3,'lab','auth',$4,$5)`, cfg.Version, sensor, sensor+"-auth", mapping.ValidFrom, mapping.ValidUntil)
		defer db.ExecContext(context.Background(), `DELETE FROM shared_observation_mappings WHERE sensor_id=$1`, sensor)
		if n, err := backend.RefreshPassiveRouterOwnership(ctx, sensor, roleAssessment, roleRefs[:1], true); err != nil || n != 0 {
			t.Fatalf("partial proof changed facts=%d err=%v", n, err)
		}
		var before int64
		for i, apply := range []bool{false, true, true} {
			matched, err := backend.RefreshPassiveRouterOwnership(ctx, sensor, roleAssessment, roleRefs, apply)
			if err != nil || (i == 0 && matched < 1) || (i == 1 && matched != before) || (i == 2 && matched != 0) {
				t.Fatalf("refresh ownership pass %d: facts=%d previously=%d err=%v", i, matched, before, err)
			}
			if i == 0 {
				before = matched
				var infra bool
				if err := db.QueryRowContext(ctx, `SELECT infrastructure FROM router_assessments WHERE assessment_id=$1`, roleAssessment).Scan(&infra); err != nil || !infra {
					t.Fatalf("preview changed the original classification: infra=%t err=%v", infra, err)
				}
			}
		}
	}
	defer db.ExecContext(context.Background(), `DELETE FROM account_identity_session_projection WHERE source=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM account_identity_projection_sources WHERE source=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM identity_snapshot_log WHERE source=$1`, sensor)
	defer db.ExecContext(context.Background(), `DELETE FROM identity_full_snapshots WHERE source=$1`, sensor)
	sampling, err := store.NewPostgresStore(store.PostgresOptions{DSN: pgDSN})
	if err != nil {
		t.Fatal(err)
	}
	defer sampling.Close()
	assertPriority := func(domain string, want bool) {
		t.Helper()
		keys, e := sampling.AuthenticatedRouterSamplingKeys(ctx, sensor, "lab", domain)
		_, ok := keys[sharedaccess.OutletKey{IP: netip.MustParseAddr(ip), MAC: [6]byte{2, 0, 0, 0, 0, 1}}]
		if e != nil || ok != want {
			t.Fatalf("capture priority scope=%s included=%t want=%t err=%v", domain, ok, want, e)
		}
	}
	assertPriority("mirror", basis == sharedaccess.AuthenticatedRouter)
	assertPriority("other", false)
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
 VALUES($1,$2,$3,$4,$5,$4,$5)`, sensor, path, epoch, segmentID, now)
	queue := store.StreamSharedJobQueue{DB: db, RequiredSources: map[string]string{path: event.Source}}
	for attempt := 0; attempt < 2; attempt++ {
		if err = queue.MarkStreamSharedJobs(ctx, segmentID, segment); err != nil {
			t.Fatal(err)
		}
		if did, e := backend.ResolveSharedGateway(ctx, cfg, now); e != nil || did != (basis == "ieee1905_association" && attempt == 0) {
			t.Fatalf("gateway resolution: attempt=%d worked=%t error=%v", attempt, did, e)
		}
		if attempt == 0 && basis == sharedaccess.AuthenticatedRouter {
			bridge := sensor + "-health"
			exec(`INSERT INTO identity_bridge_configs(bridge_id,desired_host) VALUES($1,'localhost')`, bridge)
			defer db.ExecContext(ctx, `DELETE FROM identity_bridge_configs WHERE bridge_id=$1`, bridge)
			defer db.ExecContext(ctx, `DELETE FROM shared_identity_health_intervals WHERE bridge_id=$1`, bridge)
			exec(`INSERT INTO identity_bridge_runtime(bridge_id,state,online_channel_state,event_channel_state,snapshot_state,heartbeat_at,queue_sample_error)
 VALUES($1,'healthy','healthy','healthy','healthy',$2,false)`, bridge, now)
			checked := cfg
			auth := mapping
			auth.HealthBridgeID = bridge
			checked.IdentityMappings = []sharedaccess.IdentityMapping{auth}
			for _, packetHealthy := range []bool{true, false} {
				pending := 0
				if packetHealthy {
					pending = 1
				}
				exec(`UPDATE identity_bridge_runtime SET source_queue=$2 WHERE bridge_id=$1`, bridge, pending)
				exec(`DELETE FROM shared_identity_health_intervals WHERE bridge_id=$1`, bridge)
				exec(`INSERT INTO shared_identity_health_intervals(bridge_id,valid_from,valid_to,healthy)
 VALUES($1,$2,$3,$4),($1,$3,NULL,NOT $4)`, bridge, now.Add(-time.Minute), now.Add(-10*time.Second), packetHealthy)
				w, a, e := backend.ReadSharedObservation(ctx, store.SharedObservationScope{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", IP: ip}, checked, now)
				if e != nil || w.HasRouterProof() != packetHealthy || (a.AccountID == sensor) != packetHealthy {
					t.Errorf("packet health=%t current queue=%d: proof=%t attributed=%t error=%v", packetHealthy, pending, w.HasRouterProof(), a.AccountID == sensor, e)
				}
			}
		}
		if attempt == 0 {
			exec(`INSERT INTO endpoint_entities(endpoint_id,primary_mac,registration_status,ownership_class)
 VALUES($1,$2,'registered','infrastructure')`, sensor, gatewayMAC)
			defer db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, sensor)
			assertPriority("mirror", false)
			window, _, e := backend.ReadSharedObservation(ctx, store.SharedObservationScope{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", IP: ip}, cfg, now)
			if e != nil || !slices.Contains(window.Conflicts, "infrastructure_ownership") || window.HasRouterProof() {
				t.Fatalf("registered infrastructure was eligible: router=%t conflicts=%v err=%v", window.HasRouterProof(), window.Conflicts, e)
			}
			if outcome != "infrastructure_ownership" {
				exec(`DELETE FROM endpoint_entities WHERE endpoint_id=$1`, sensor)
			}
		}
		did, e := s.processSharedObservation(ctx, now)
		if e != nil || did != (attempt == 0) {
			t.Fatalf("process: %v %v", did, e)
		}
	}
	if outcome != "matched" {
		// Flush the regular case synchronizer even for suppressed observations.
		// Then check for side effects against the durable tables.
		s.exceptions = newExceptionManager(db)
		s.operations.streamSharedEvidenceLoader = backend.ReadStreamSharedCaseEvidence
		if err := s.syncAutomaticCasesContext(ctx, sensor, "10m"); err != nil {
			t.Fatal(err)
		}
		if outcome == "infrastructure_ownership" {
			var excluded bool
			err := db.QueryRowContext(ctx, `SELECT bool_and(result <> 'matched' AND document->'evidence'->'conflicts' ? 'infrastructure_ownership')
 FROM policy_decision_records WHERE document->'evidence'->>'sensor_id'=$1`, sensor).Scan(&excluded)
			if err != nil || !excluded {
				t.Fatalf("registered infrastructure produced no exclusion: excluded=%t err=%v", excluded, err)
			}
		} else {
			var verified string
			if err := db.QueryRowContext(ctx, `SELECT d.document->'evidence'->'outlet_activity'->>'event_id' FROM policy_decision_records d
 JOIN shared_access_findings f USING(observation_id) JOIN shared_behavior_observations o USING(observation_id)
 WHERE d.account_id=$1 AND d.result='whitelist_suppressed' AND f.outcome='exempt' AND f.case_id='' AND f.action_id=''
 AND o.observation->'whitelist_match'->>'entry_id'=d.document->'whitelist_match'->>'entry_id'`, sensor).Scan(&verified); err != nil {
				t.Fatal(err)
			}
			scope := store.SharedObservationScope{SensorID: sensor, CampusID: "lab", AccessDomain: "mirror", IP: ip}
			rows, err := archive.ListStreamSharedCaseSignalRefs(ctx, scope, scopeID, event.Source, epoch, ip, now.Add(-time.Minute), now, []string{verified})
			if err != nil || len(rows) != 1 {
				t.Fatalf("exempt observation no longer locates its original %q: %v %v", verified, rows, err)
			}
			refs := append(slices.Clone(roleRefs), rows[0].Body)
			originals, err := archive.GetStreamEventsByRefs(ctx, refs)
			if err != nil || len(originals) != len(refs) || originals[rows[0].Body].EventID != verified {
				t.Fatalf("exempt originals did not verify: %d/%d %v", len(originals), len(refs), err)
			}
		}
		for _, table := range []string{"risk_cases", "enforcement_actions", "behavior_report_outbox"} {
			var n int
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE account_id=$1", sensor).Scan(&n); err != nil || n != 0 {
				t.Fatalf("exempt account %s count=%d err=%v", table, n, err)
			}
		}
		return
	}
	var n int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM policy_decision_records WHERE account_id=$1 AND result='matched' AND document->>'mode'='manual' AND document->>'delivery_status'='record_only'`, sensor).Scan(&n); err != nil || n != 1 {
		var detail string
		_ = db.QueryRowContext(ctx, `SELECT coalesce(string_agg(result||' '||coalesce((document->'reasons')::text,''),','),'no decisions') FROM policy_decision_records WHERE document->'evidence'->>'sensor_id'=$1`, sensor).Scan(&detail)
		t.Fatalf("exactly one hit: %d %v, decisions: %s", n, err, detail)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM enforcement_actions WHERE account_id=$1 AND status='recorded' AND mode='record_only' AND coalesce(connector_id,'')='' AND coalesce(remote_action_id,'')=''`, sensor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one record-only action: %d %v", n, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM behavior_report_outbox WHERE account_id=$1 AND channel_id=$1
 AND status='recorded' AND payload->>'external_request_sent'='false'`, sensor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one record-only report: %d %v", n, err)
	}
	var storedBasis string
	if err = db.QueryRowContext(ctx, `SELECT basis FROM shared_access_findings WHERE account_id=$1 AND outcome='confirmed'`, sensor).Scan(&storedBasis); err != nil || storedBasis != basis {
		t.Fatalf("confirmed finding: got %q, want %q: %v", storedBasis, basis, err)
	}
	s.exceptions = newExceptionManager(db)
	s.operations.streamSharedEvidenceLoader = backend.ReadStreamSharedCaseEvidence
	for attempt := 0; attempt < 2; attempt++ {
		if err := s.syncAutomaticCasesContext(ctx, sensor, "10m"); err != nil {
			t.Fatalf("synchronize sharing case: %v", err)
		}
	}
	if err := db.QueryRowContext(ctx, `SELECT count(DISTINCT c.case_id) FROM shared_access_findings f
	 JOIN risk_cases c ON c.case_id=f.case_id JOIN enforcement_actions a ON a.action_id=f.action_id AND a.case_id=c.case_id
	 WHERE f.account_id=$1 AND f.outcome='confirmed' AND NOT f.case_pending AND a.mode='record_only'`, sensor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("durable case linked to the recorded action: %d %v", n, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM stream_shared_case_evidence e
	 JOIN shared_access_findings f ON e.case_id=f.case_id WHERE f.account_id=$1 AND e.epoch=$2`, sensor, epoch).Scan(&n); err != nil || n != 1 {
		t.Fatalf("protected mirror original: %d %v", n, err)
	}
	if basis == sharedaccess.AuthenticatedRouter {
		var raw, roleEvent string
		if err = db.QueryRowContext(ctx, `SELECT s.evidence->'shared_access'->>'role_value_excerpt',s.evidence->'shared_access'->>'role_event_id'
		 FROM risk_case_evidence_snapshots s JOIN shared_access_findings f USING(case_id) WHERE f.account_id=$1 LIMIT 1`, sensor).Scan(&raw, &roleEvent); err != nil || raw != "uuid:"+sensor+"::urn:schemas-upnp-org:device:InternetGatewayDevice:1" || roleEvent != sensor+"-igd" {
			t.Fatalf("immutable router role evidence: %q %q %v", raw, roleEvent, err)
		}
	}
	progress, err := s.readSharedStreamProgress(ctx, time.Now())
	if err != nil || len(progress) != 2 {
		t.Fatalf("shared source progress: %+v %v", progress, err)
	}
	for _, source := range progress {
		if source.Owner == event.Source && (source.State != "healthy" || source.AcceptedSegment != segmentID || source.SharedConfirmedSegment != segmentID) {
			t.Fatalf("packet status does not match durable work: %+v", source)
		}
	}
	for _, table := range tables {
		var n int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != before[table] {
			t.Fatalf("side effect in %s: before=%d after=%d err=%v", table, before[table], n, err)
		}
	}
	t.Run("historical evidence after expiry", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		var original []byte
		if err := tx.QueryRowContext(ctx, `SELECT o.observation FROM shared_access_findings f JOIN shared_behavior_observations o USING(observation_id) WHERE f.account_id=$1 AND f.outcome='confirmed'`, sensor).Scan(&original); err != nil {
			t.Fatal(err)
		}
		var live sharedaccess.BehaviorAssessment
		if err := json.Unmarshal(original, &live); err != nil {
			t.Fatal(err)
		}
		expired := live
		expired.Current, expired.Status, expired.AccountID = false, "candidate", ""
		expired.Router, expired.OutletEvidence = sharedaccess.BehaviorRouterContext{}, nil
		persist := func(item sharedaccess.BehaviorAssessment, wantChange bool) {
			t.Helper()
			changed, err := store.PersistSharedObservationTx(ctx, tx, item)
			if err != nil || changed != wantChange {
				t.Fatalf("persist current=%t changed=%t want=%t err=%v", item.Current, changed, wantChange, err)
			}
		}
		persist(expired, true)
		var preserved bool
		if err := tx.QueryRowContext(ctx, `SELECT NOT current AND status='confirmed' AND observation=jsonb_set($2::jsonb,'{current}','false') FROM shared_behavior_observations WHERE observation_id=$1`, live.ObservationID, string(original)).Scan(&preserved); err != nil || !preserved {
			t.Fatalf("expiry lost the historical verdict or evidence: preserved=%t err=%v", preserved, err)
		}
		live.ObservationID += "-new"
		persist(live, true)
		persist(expired, false)
		if err := tx.QueryRowContext(ctx, `SELECT current FROM shared_behavior_observations WHERE observation_id=$1`, live.ObservationID).Scan(&preserved); err != nil || !preserved {
			t.Fatalf("a late expiry retired the newer observation: current=%t err=%v", preserved, err)
		}
	})
	t.Run("older expired detail retains its audited account", func(t *testing.T) {
		// Earlier releases could replace the detail on expiry while the finding
		// kept the original account. Exercise the period report's actual drilldown.
		exec(`UPDATE shared_behavior_observations o SET current=false,observation=o.observation-'account_id'-'authenticated_outlet'
 FROM shared_access_findings f WHERE f.observation_id=o.observation_id AND f.account_id=$1`, sensor)
		page, err := backend.ListSharedBehavior(ctx, store.SharedBehaviorQuery{View: "period", Outcome: "accounts", Keyword: sensor,
			SearchAccount: true, From: now.Add(-10 * time.Minute), To: now.Add(time.Minute)})
		if err != nil || len(page.Items) != 1 || page.Items[0].Current || page.Items[0].AccountID != sensor || len(page.Items[0].OutletEvidence) != 0 {
			t.Fatalf("period lookup of an expired account: count=%d err=%v", len(page.Items), err)
		}
	})
	if basis == sharedaccess.AuthenticatedRouter {
		t.Run("two hits on one session have two local reports", func(t *testing.T) {
			nextAt := now.Add(-time.Second)
			event.EventID = sensor + "-second-syn"
			event.Timestamp = nextAt.Format(time.RFC3339Nano)
			event.Payload["outlet_activity"] = sharedaccess.OutletActivity{MAC: gatewayMAC, EventID: event.EventID, At: nextAt}
			segment.StartOffset, segment.EndOffset = segment.EndOffset, segment.EndOffset+1
			segment.AcceptedAt = time.Now().UTC()
			segment.Events = []normalized.Event{event}
			id := streamlog.SourceSegmentID(segment)
			if err := archive.WriteStreamBody(ctx, id, segment); err != nil {
				t.Fatal(err)
			}
			if err := archive.WriteStreamSearch(ctx, id, segment); err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE stream_shared_source_runtime SET accepted_segment=$3,archived_segment=$3,accepted_at=$4,archived_at=$4 WHERE sensor_id=$1 AND epoch=$2`, sensor, epoch, id, segment.AcceptedAt)
			for attempt := 0; attempt < 2; attempt++ {
				if err := queue.MarkStreamSharedJobs(ctx, id, segment); err != nil {
					t.Fatal(err)
				}
				did, err := s.processSharedObservation(ctx, time.Now().UTC())
				if err != nil || did != (attempt == 0) {
					t.Fatalf("process second segment attempt %d: did=%v err=%v", attempt, did, err)
				}
			}
			var hits, episodes, reports, reportedHits int
			if err := db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT execution_id) FROM policy_decision_records WHERE account_id=$1 AND result='matched'`, sensor).Scan(&hits, &episodes); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT d.decision_id) FROM behavior_report_outbox o JOIN policy_decision_records d ON d.decision_id=o.payload->>'policy_decision_id' WHERE o.account_id=$1 AND o.channel_id=$1 AND o.status='recorded' AND o.payload->>'external_request_sent'='false'`, sensor).Scan(&reports, &reportedHits); err != nil {
				t.Fatal(err)
			}
			if hits != 2 || episodes != 1 || reports != 2 || reportedHits != 2 {
				t.Fatalf("wanted two distinct hits and reports on one execution, got hits=%d executions=%d reports=%d reported hits=%d", hits, episodes, reports, reportedHits)
			}
		})
	}

}
