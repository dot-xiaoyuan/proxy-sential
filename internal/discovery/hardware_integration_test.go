package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"proxy-sentinel/internal/census"
	"proxy-sentinel/internal/fingerprint"
)

func hardwareIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not configured")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("hardware_test_%d", time.Now().UnixNano())
	if _, err = db.Exec(`CREATE SCHEMA ` + schema + `;SET search_path TO ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); db.Close() })
	for _, name := range []string{"235_passive_census_projection.sql", "236_passive_census_terminal_scope.sql", "237_passive_census_recent_scope_index.sql", "238_passive_census_pending_batches.sql", "239_passive_census_expiry_index.sql", "240_passive_census_terminal_mac.sql", "241_passive_hardware_projection.sql", "242_passive_hardware_claim_index.sql", "243_passive_hardware_runtime.sql", "244_passive_hardware_backfill_gaps.sql"} {
		raw, err := os.ReadFile(filepath.Join("../../migrations/postgres", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
	_, err = db.Exec(`CREATE TABLE discovery_observation_latest(id text PRIMARY KEY,device_key text,origin text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,data jsonb);
 CREATE TABLE discovery_identity_links(observation_id text,endpoint_id text,basis jsonb);
 CREATE TABLE device_address_leases(event_id text,action text,sensor_id text,ip inet,campus_id text,endpoint_id text);
 CREATE TABLE endpoint_recognition_summary(endpoint_id text,role text,os_family text,summary jsonb,confidence double precision,conflict boolean);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestHardwareProjectionPostgresConflictsRuleRetractionAndRecovery(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	o := hardwareTestObservation(now)
	enqueueHardwareTest(t, db, o)
	processHardwareTest(t, db)
	// A different exact model in the same type creates model conflict only.
	newer := hardwareTestObservation(now.Add(time.Second))
	newer.ID = "model2"
	newer.EventID = "model2"
	newer.ModelName = "DS-K1T343MFX"
	newer.Evidence.Payload["product_model"] = newer.ModelName
	enqueueHardwareTest(t, db, newer)
	processHardwareTest(t, db)
	var typ, status, modelStatus string
	db.QueryRow(`SELECT hardware_type,hardware_type_status,hardware_model_status FROM passive_hardware_current`).Scan(&typ, &status, &modelStatus)
	if typ != "access_control" || status != "identified" || modelStatus != "conflict" {
		t.Fatalf("model conflict corrupted type: %s %s %s", typ, status, modelStatus)
	}
	// A camera self-report conflicts with the door terminal, never latest-wins.
	camera := hardwareTestObservation(now.Add(2 * time.Second))
	camera.ID = "camera"
	camera.EventID = "camera"
	camera.ModelName = "DS-2CD2143G2-I"
	camera.Evidence.Payload["product_model"] = camera.ModelName
	enqueueHardwareTest(t, db, camera)
	processHardwareTest(t, db)
	db.QueryRow(`SELECT hardware_type_status FROM passive_hardware_current`).Scan(&status)
	if status != "conflict" {
		t.Fatalf("contradictory product not conflict: %s", status)
	}
	// Rollback after claiming a row leaves it available after a worker crash.
	key := HardwareIdentityKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF, o.MAC)
	_, err := db.Exec(`INSERT INTO passive_hardware_dirty(identity_key,sensor_id,reason) VALUES($1,'sensor','crash-test')`, key)
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := db.Begin()
	var claimed string
	if err = tx.QueryRow(`SELECT identity_key FROM passive_hardware_dirty FOR UPDATE SKIP LOCKED`).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	processHardwareTest(t, db)
	var count int
	db.QueryRow(`SELECT count(*) FROM passive_hardware_dirty`).Scan(&count)
	if count != 0 {
		t.Fatal("abandoned claim not recovered")
	}
	// A second process skips a live claim instead of racing its current write.
	var schema string
	if err = db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	otherDB, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	otherDB.SetMaxOpenConns(1)
	defer otherDB.Close()
	if _, err = otherDB.Exec(`SET search_path TO ` + schema); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO passive_hardware_dirty(identity_key,sensor_id,reason) VALUES($1,'sensor','concurrent-test')`, key); err != nil {
		t.Fatal(err)
	}
	tx, _ = db.Begin()
	if err = tx.QueryRow(`SELECT identity_key FROM passive_hardware_dirty FOR UPDATE`).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	if processed, err := ProcessHardwareProjection(ctx, otherDB, "sensor", 100); err != nil || processed != 0 {
		tx.Rollback()
		t.Fatalf("concurrent worker claimed locked identity: %d %v", processed, err)
	}
	tx.Rollback()
	processHardwareTest(t, db)
	// Rule removal must revisit silent identities through stored dependencies.
	var rule, version string
	if err = db.QueryRow(`SELECT rule_id,rule_version FROM passive_hardware_rule_dependencies ORDER BY rule_id LIMIT 1`).Scan(&rule, &version); err != nil {
		t.Fatal(err)
	}
	oldDefault := fingerprint.Default()
	replacement := *oldDefault
	catalog := []byte(`{"version":"test-rules-retracted","converter_version":"test","models":[],"snmp":[],"recog_files":{},"sources":[]}`)
	if err = replacement.LoadHardwareCatalog(catalog, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	fingerprint.SetDefault(&replacement)
	defer fingerprint.SetDefault(oldDefault)
	queued, err := RequeueHardwareRule(ctx, db, rule, version)
	if err != nil || queued != 1 {
		t.Fatalf("dependency enqueue=%d err=%v", queued, err)
	}
	processHardwareTest(t, db)
	db.QueryRow(`SELECT hardware_type_status FROM passive_hardware_current`).Scan(&status)
	if status == "identified" || status == "conflict" {
		t.Fatalf("retracted rules still determine type: %s", status)
	}
}

func TestHardwareProjectionPostgresOverflowPreservesRetryState(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	o := hardwareTestObservation(time.Now().UTC().Add(-time.Minute))
	enqueueHardwareTest(t, db, o)
	processHardwareTest(t, db)
	_, err := db.Exec(`INSERT INTO passive_hardware_facts(identity_key,fact_key,claim_key,sensor_id,campus_id,access_domain,vlan,vrf,mac,device_key,source,first_seen,observed_at,active_until,revoked,evidence_id,data)
 SELECT identity_key,'overflow-'||i,claim_key,sensor_id,campus_id,access_domain,vlan,vrf,mac,device_key,source,first_seen,observed_at,active_until,revoked,evidence_id,data FROM passive_hardware_facts CROSS JOIN generate_series(1,512) i;
 INSERT INTO passive_hardware_dirty(identity_key,sensor_id,reason) SELECT identity_key,sensor_id,'overflow-test' FROM passive_hardware_current`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ProcessHardwareProjection(ctx, db, "sensor", 100); err == nil {
		t.Fatal("overflow silently completed")
	}
	var attempts int
	var message, status string
	var first, updated time.Time
	if err = db.QueryRow(`SELECT attempts,last_error,first_enqueued_at,updated_at FROM passive_hardware_dirty`).Scan(&attempts, &message, &first, &updated); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || message == "" {
		t.Fatalf("overflow retry state missing: %d %q", attempts, message)
	}
	db.QueryRow(`SELECT hardware_type_status FROM passive_hardware_current`).Scan(&status)
	if status != "identified" {
		t.Fatal("failed recompute erased last valid current projection")
	}
}

// This is deliberately opt-in: it measures a synthetic campus-sized replay on
// local PostgreSQL, not a live 204 acceptance test or an HTTP latency promise.
func TestHardwareProjectionPostgresScale5000(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_HARDWARE_SCALE_TEST") != "true" {
		t.Skip("opt-in 5000 identity replay")
	}
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Second)
	observations := make([]Observation, 0, 10000)
	for i := 0; i < 5000; i++ {
		mac := fmt.Sprintf("00:11:22:%02x:%02x:%02x", i>>16, (i>>8)&255, i&255)
		o := hardwareTestObservation(now.Add(-48 * time.Hour))
		o.MAC = mac
		o.Evidence.Payload["claimed_mac"] = mac
		o.Evidence.Payload["l2_source_mac"] = mac
		o.ID = fmt.Sprintf("model-%d", i)
		o.EventID = o.ID
		observations = append(observations, o)
		a := o
		a.Origin = "arp"
		a.ID = fmt.Sprintf("arp-%d", i)
		a.EventID = a.ID
		a.ObservedAt = now
		a.ValidUntil = now.Add(10 * time.Minute)
		a.ModelName = ""
		observations = append(observations, a)
	}
	start := time.Now()
	enqueueHardwareTest(t, db, observations...)
	enqueueMS := time.Since(start).Milliseconds()
	start = time.Now()
	processed := 0
	for processed < 5000 {
		n, err := ProcessHardwareProjection(ctx, db, "sensor", 100)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("projection stopped before completing replay")
		}
		processed += n
	}
	projectMS := time.Since(start).Milliseconds()
	_, err := db.Exec(`INSERT INTO discovery_observation_latest SELECT identity_key,device_key,'arp',last_seen,active_until,false,jsonb_build_object('id',identity_key,'event_id',identity_key,'node',sensor_id,'site',campus_id,'domain',access_domain,'vlan',vlan,'vrf',vrf,'mac',mac,'origin','arp','observed_at',last_seen,'valid_until',active_until,'confidence','confirmed') FROM passive_hardware_current;
 INSERT INTO passive_census_identifier_current(scope_key,sensor_id,campus_id,access_domain,vlan,vrf,kind,value,first_seen,last_seen,last_event_id,last_source) SELECT scope_key,sensor_id,campus_id,access_domain,vlan,vrf,'mac',mac,first_seen,last_seen,identity_key,'arp' FROM passive_hardware_current;
 INSERT INTO passive_census_runtime(sensor_id,available_from,last_source_at,last_success_at) VALUES('sensor',now()-interval '3 days',now(),now()); ANALYZE passive_hardware_current; ANALYZE passive_census_identifier_current; ANALYZE discovery_observation_latest;`)
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{DB: db, HardwareV2: true}
	cr := census.Repository{DB: db, HardwareV2: true}
	samples := map[string][]float64{"metadata": {}, "page": {}, "census": {}}
	for i := 0; i < 60; i++ {
		tx, _ := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		q := DeviceQuery{Mode: "passive", State: "identified", Limit: 50}
		start = time.Now()
		meta, err := repo.DevicesIndexedMetadataSnapshot(ctx, tx, q)
		samples["metadata"] = append(samples["metadata"], float64(time.Since(start).Microseconds())/1000)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if meta.Identified != 5000 {
			tx.Rollback()
			t.Fatalf("metadata count %d", meta.Identified)
		}
		start = time.Now()
		page, err := repo.DevicesIndexedSnapshot(ctx, tx, q)
		samples["page"] = append(samples["page"], float64(time.Since(start).Microseconds())/1000)
		tx.Rollback()
		if err != nil {
			t.Fatal(err)
		}
		if len(page["items"].([]DeviceView)) != 50 {
			t.Fatal("page size")
		}
		start = time.Now()
		summary, err := cr.GetSummary(ctx, census.Query{SensorID: "sensor"})
		samples["census"] = append(samples["census"], float64(time.Since(start).Microseconds())/1000)
		if err != nil {
			t.Fatal(err)
		}
		if summary.IdentifiedTerminals != 5000 {
			t.Fatalf("census count %d", summary.IdentifiedTerminals)
		}
	}
	var bytes int64
	db.QueryRow(`SELECT sum(pg_total_relation_size(oid)) FROM pg_class WHERE relname IN('passive_hardware_facts','passive_hardware_current','passive_hardware_dirty','passive_hardware_rule_dependencies','passive_hardware_changes') AND relnamespace=current_schema()::regnamespace`).Scan(&bytes)
	t.Logf("local synthetic 5000 identities/10000 facts: enqueue=%dms project=%dms relation_bytes=%d pending=0", enqueueMS, projectMS, bytes)
	for _, name := range []string{"metadata", "page", "census"} {
		v := samples[name]
		sort.Float64s(v)
		t.Logf("local PG %s samples=%d P95=%.3fms P99=%.3fms", name, len(v), v[int(float64(len(v))*.95)-1], v[len(v)-1])
	}
}

func enqueueHardwareTest(t *testing.T, db *sql.DB, obs ...Observation) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = EnqueueHardwareObservations(context.Background(), tx, obs); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func processHardwareTest(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := ProcessHardwareProjection(context.Background(), db, "sensor", 100); err != nil {
		t.Fatal(err)
	}
}

func TestHardwareProjectionPostgresLifecycleAndConsistentReaders(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	old := hardwareTestObservation(now.Add(-48 * time.Hour))
	old.ValidUntil = old.ObservedAt.Add(time.Minute)
	recent := old
	recent.Origin = "arp"
	recent.ID = "arp-now"
	recent.EventID = "arp-now"
	recent.ModelName = ""
	recent.ObservedAt = now
	recent.ValidUntil = now.Add(time.Minute)
	enqueueHardwareTest(t, db, old, recent)
	processHardwareTest(t, db)
	var typ, status string
	var version int
	if err := db.QueryRow(`SELECT hardware_type,hardware_type_status,result_version FROM passive_hardware_current`).Scan(&typ, &status, &version); err != nil {
		t.Fatal(err)
	}
	if typ != "access_control" || status != "identified" {
		t.Fatalf("expired hardware support lost: %s %s", typ, status)
	}
	enqueueHardwareTest(t, db, old, recent)
	processHardwareTest(t, db)
	var nextVersion int
	db.QueryRow(`SELECT result_version FROM passive_hardware_current`).Scan(&nextVersion)
	if nextVersion != version {
		t.Fatal("duplicate rewrote result")
	}
	// Metadata, page and cursor export all use the same current hardware conclusion.
	raw, _ := json.Marshal(recent)
	_, err := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,$3,$4,$5,false,$6)`, recent.ID, recent.Key(), recent.Origin, recent.ObservedAt, recent.ValidUntil, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{DB: db, HardwareV2: true}
	q := DeviceQuery{Mode: "passive", State: "identified", DeviceType: "access_control", Window: 24 * time.Hour}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := repo.DevicesIndexedMetadataSnapshot(ctx, tx, q)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	q.Export = true
	page, err := repo.DevicesIndexedSnapshot(ctx, tx, q)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	tx.Rollback()
	items := page["items"].([]DeviceView)
	if meta.Identified != 1 || len(items) != 1 || items[0].HardwareType != "access_control" || items[0].DeviceType != "access_control" {
		t.Fatalf("reader disagreement: %+v %+v", meta, items)
	}
	scope := census.ScopeKey(recent.Node, recent.Site, recent.Domain, recent.VLAN, recent.VRF)
	_, err = db.Exec(`INSERT INTO passive_census_identifier_current(scope_key,sensor_id,campus_id,access_domain,vlan,vrf,kind,value,first_seen,last_seen,last_event_id,last_source) VALUES($1,'sensor','campus','access','20','','mac',$2,$3,$3,'arp-now','arp');INSERT INTO passive_census_runtime(sensor_id,available_from,last_source_at,last_success_at) VALUES('sensor',now()-interval '3 days',now(),now())`, scope, recent.MAC, now)
	// pgx extended protocol does not allow multiple statements with arguments.
	if err != nil {
		_, err = db.Exec(`INSERT INTO passive_census_identifier_current(scope_key,sensor_id,campus_id,access_domain,vlan,vrf,kind,value,first_seen,last_seen,last_event_id,last_source) VALUES($1,'sensor','campus','access','20','','mac',$2,$3,$3,'arp-now','arp')`, scope, recent.MAC, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO passive_census_runtime(sensor_id,available_from,last_source_at,last_success_at) VALUES('sensor',now()-interval '3 days',now(),now())`); err != nil {
			t.Fatal(err)
		}
	}
	cr := census.Repository{DB: db, HardwareV2: true}
	cq := census.Query{SensorID: "sensor", Kind: "terminal"}
	summary, err := cr.GetSummary(ctx, cq)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := cr.GetPage(ctx, cq)
	if err != nil {
		t.Fatal(err)
	}
	if summary.IdentifiedTerminals != 1 || len(cp.Items) != 1 || cp.Items[0].EffectiveType != "access_control" {
		t.Fatalf("census disagreement: %+v %+v", summary, cp)
	}
	// Withdrawal wins over older input. The current type remains traceable but revoked.
	withdrawn := old
	withdrawn.Withdrawn = true
	withdrawn.ObservedAt = now.Add(-time.Second)
	enqueueHardwareTest(t, db, withdrawn)
	processHardwareTest(t, db)
	enqueueHardwareTest(t, db, old)
	processHardwareTest(t, db)
	if err = db.QueryRow(`SELECT hardware_type_status FROM passive_hardware_current`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "revoked" {
		t.Fatalf("late replay resurrected withdrawn type: %s", status)
	}
	// Transaction rollback never commits a fact without its outbox (or vice versa).
	tx, _ = db.Begin()
	other := hardwareTestObservation(now)
	other.VLAN = "21"
	if err = EnqueueHardwareObservations(ctx, tx, []Observation{other}); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	var count int
	db.QueryRow(`SELECT count(*) FROM passive_hardware_dirty`).Scan(&count)
	if count != 0 {
		t.Fatal("rollback left orphan dirty task")
	}
}

func TestHardwareProjectionPostgresSpecialScopeAndLateTime(t *testing.T) {
	db := hardwareIntegrationDB(t)
	now := time.Now().UTC().Add(-time.Minute)
	o := hardwareTestObservation(now)
	o.Site = "校区<&>\u2028\u2029"
	o.Domain = "楼宇\"\\\t\n\b\f\r\x01"
	var sqlKey string
	if err := db.QueryRow(`SELECT jsonb_build_array('identity',$1::text,$2::text,$3::text,$4::text,$5::text,'mac',$6::text)::text`, o.Node, o.Site, o.Domain, o.VLAN, o.VRF, o.MAC).Scan(&sqlKey); err != nil {
		t.Fatal(err)
	}
	goKey := HardwareIdentityKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF, o.MAC)
	if goKey != sqlKey {
		t.Fatalf("scope identity encoding differs: Go=%q SQL=%q", goKey, sqlKey)
	}
	enqueueHardwareTest(t, db, o)
	processHardwareTest(t, db)
	raw, _ := json.Marshal(o)
	if _, err := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,$3,$4,$5,false,$6)`, o.ID, o.Key(), o.Origin, o.ObservedAt, o.ValidUntil, string(raw)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	page, err := (Repository{DB: db, HardwareV2: true}).DevicesIndexedSnapshot(context.Background(), tx, DeviceQuery{Mode: "passive", DeviceType: "access_control"})
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if items := page["items"].([]DeviceView); len(items) != 1 || items[0].HardwareType != "access_control" {
		t.Fatalf("special scope lost list projection: %+v", items)
	}
	earliest := o
	earliest.ObservedAt = now.Add(-20 * 24 * time.Hour)
	earliest.ValidUntil = earliest.ObservedAt.Add(time.Minute)
	enqueueHardwareTest(t, db, earliest)
	processHardwareTest(t, db)
	var first, last time.Time
	var status string
	if err := db.QueryRow(`SELECT first_seen,last_seen,hardware_type_status FROM passive_hardware_current WHERE identity_key=$1`, sqlKey).Scan(&first, &last, &status); err != nil {
		t.Fatal(err)
	}
	if first.Sub(earliest.ObservedAt).Abs() > time.Microsecond || last.Sub(o.ObservedAt).Abs() > time.Microsecond || status != "identified" {
		t.Fatalf("late first-seen changed current conclusion: %v %v %s", first, last, status)
	}
	f, _ := HardwareFactFromObservation(o)
	f.Revoked = true
	f.ActiveUntil = now.Add(24 * time.Hour)
	s, err := EvaluateHardwareFacts([]HardwareFact{*f}, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if s.ActiveUntil.After(now) {
		t.Fatal("revoked first fact kept activity alive")
	}
}
