package controlplane

import (
	"context"
	"database/sql"
	"fmt"
)

// Synthetic fixtures are restricted by the opt-in fixture server's database
// checks. They cover nonempty identities, recognition, signals and evidence;
// no field data or credentials are copied into the benchmark environment.
func seedBenchmarkIdentityAndEvidence(db *sql.DB) error {
	ctx := context.Background()
	var database string
	if err := db.QueryRowContext(ctx, "SELECT current_database()").Scan(&database); err != nil {
		return err
	}
	if database != "sentinel_benchmark" {
		return fmt.Errorf("refuse fixture seed outside sentinel_benchmark")
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS benchmark_fixture_state(name text PRIMARY KEY,completed_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var seeded bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM benchmark_fixture_state WHERE name='identity-evidence-v1')`).Scan(&seeded); err != nil {
		return err
	}
	if seeded {
		return seedBenchmarkRecognitionAttributes(db)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`INSERT INTO sensors(sensor_id,display_name,collector_kind) VALUES('bench-scale-20260917','Isolated benchmark collector','fixture') ON CONFLICT DO NOTHING`,
		`INSERT INTO collector_runs(run_id,sensor_id,started_at,finished_at,normalized_read,normalized_emitted,evidence_count,risk_count) VALUES('bench-scale-run','bench-scale-20260917',now()-interval '6 days',now(),10000000,10000000,1700000,47) ON CONFLICT DO NOTHING`,
		`INSERT INTO endpoint_entities(endpoint_id,primary_mac,first_seen,last_seen,identity_confidence,registration_status,owner_account,attributes) SELECT 'mac:00:10:'||substring(lpad(to_hex(n),8,'0'),1,2)||':'||substring(lpad(to_hex(n),8,'0'),3,2)||':'||substring(lpad(to_hex(n),8,'0'),5,2)||':'||substring(lpad(to_hex(n),8,'0'),7,2),'00:10:'||substring(lpad(to_hex(n),8,'0'),1,2)||':'||substring(lpad(to_hex(n),8,'0'),3,2)||':'||substring(lpad(to_hex(n),8,'0'),5,2)||':'||substring(lpad(to_hex(n),8,'0'),7,2),now()-interval '6 days',now(),.95,'registered','bench-account-'||(n%1000),jsonb_build_object('campus_id','bench-campus','source','benchmark-fixture') FROM generate_series(0,23999)n ON CONFLICT DO NOTHING`,
		`INSERT INTO endpoint_device_profiles(endpoint_id,vendor,brand,model,device_type,os_family,recognition_confidence,recognition_source,fingerprint_version,brand_confidence,os_family_confidence) SELECT endpoint_id,(ARRAY['Apple','Huawei','vivo','Samsung','Dell','Intel','Unknown']::text[])[n%7+1],(ARRAY['Apple','Huawei','vivo','Samsung','Dell','','']::text[])[n%7+1],'Synthetic model '||(n%7),(ARRAY['phone','phone','phone','phone','computer','computer','unknown']::text[])[n%7+1],(ARRAY['iOS','Android','Android','Android','Windows','Linux','macOS']::text[])[n%7+1],.95,'fixture','benchmark-v1',.95,.95 FROM (SELECT endpoint_id,row_number() OVER(ORDER BY endpoint_id)::int-1 n FROM endpoint_entities WHERE endpoint_id LIKE 'mac:00:10:%') e ON CONFLICT DO NOTHING`,
		`INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,mac,access_id,source,started_at,identity_confidence,campus_id,session_status,policy_metadata) SELECT 'bench-session-'||n,'bench-account-'||(n%1000),endpoint_id,('10.0.'||(n/250)||'.'||(n%250+1))::inet,primary_mac,'bench-ap','benchmark-fixture',now()-interval '1 hour',.95,'bench-campus','online',jsonb_build_object('heartbeat_at',now(),'device_class',CASE WHEN n%2=0 THEN 'mobile' ELSE 'pc' END) FROM (SELECT endpoint_id,primary_mac,row_number() OVER(ORDER BY endpoint_id)::int-1 n FROM endpoint_entities WHERE endpoint_id LIKE 'mac:00:10:%') e ON CONFLICT DO NOTHING`,
		`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,entity_role,ip,mac,source,first_seen,last_seen,identity_confidence,event_ids_sample) SELECT 'bench-identity-'||session_id,endpoint_id,account_id,'endpoint',ip,mac,'benchmark-fixture',started_at,now(),.95,jsonb_build_array('bench-identity-'||session_id) FROM account_sessions WHERE session_id LIKE 'bench-session-%' ON CONFLICT DO NOTHING`,
		`INSERT INTO identity_access_history(event_id,endpoint_id,account_id,entity_role,access_id,access_type,ap,source,first_seen,last_seen,identity_confidence) SELECT 'bench-access-'||session_id,endpoint_id,account_id,'endpoint','bench-ap','wifi','bench-ap','benchmark-fixture',started_at,now(),.95 FROM account_sessions WHERE session_id LIKE 'bench-session-%' ON CONFLICT DO NOTHING`,
		`INSERT INTO evidence(evidence_id,ip,type,"window",score,confidence,severity,reason,samples,created_at) SELECT 'bench-scale-evidence-'||n,('10.0.'||((n%24000)/250)||'.'||(n%250+1))::inet,(ARRAY['vpn_proxy_rule_match','ttl_divergence','tls_fingerprint_divergence','ua_divergence']::text[])[n%4+1],'1h',25,.95,'high','Synthetic reproducible evidence',jsonb_build_array('bench-event-'||n),now()-((n%560000)*interval '1 second') FROM generate_series(0,1699999)n ON CONFLICT DO NOTHING`,
		`INSERT INTO device_signal_facts(sensor_id,signal_id,ip,source,kind,value,normalized_value,strength,confidence,weight,first_seen,last_seen,seen_count,event_ids_sample) SELECT 'bench-scale-20260917','bench-signal-'||n,('10.0.'||(n/250)||'.'||(n%250+1))::inet,'fixture','tls_ja3','fixture-ja3-'||(n%4),'fixture-ja3-'||(n%4),'strong',.95,20,now()-interval '1 hour',now(),10,jsonb_build_array('bench-event-'||n) FROM generate_series(0,23999)n ON CONFLICT DO NOTHING`,
		`UPDATE risk_cases SET ip=('10.0.0.'||((substring(case_id from '[0-9]+$'))::int+1))::inet,subject_id='10.0.0.'||((substring(case_id from '[0-9]+$'))::int+1) WHERE case_id LIKE 'bench-scale-case-%'`,
		`INSERT INTO risk_snapshots(ip,score,level,confidence,"window",evidence_ids,summary,recommended_action,updated_at,detection_basis) SELECT s.ip,95,'high',.95,'1h',jsonb_build_array('bench-scale-evidence-'||n),'Synthetic linked risk','review',now(),'explicit_tunnel' FROM generate_series(0,46)n JOIN account_sessions s ON s.session_id='bench-session-'||n ON CONFLICT(ip) DO UPDATE SET score=95,confidence=.95,evidence_ids=EXCLUDED.evidence_ids,detection_basis=EXCLUDED.detection_basis`,
		`INSERT INTO benchmark_fixture_state(name) VALUES('identity-evidence-v1')`,
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return seedBenchmarkRecognitionAttributes(db)
}

func seedBenchmarkRecognitionAttributes(db *sql.DB) error {
	_, err := db.ExecContext(context.Background(), `UPDATE endpoint_entities e SET attributes=e.attributes||jsonb_build_object('vendor',p.vendor,'brand',p.brand,'model',p.model,'device_type',p.device_type,'os_family',p.os_family) FROM endpoint_device_profiles p WHERE e.endpoint_id=p.endpoint_id AND e.endpoint_id LIKE 'mac:00:10:%' AND e.attributes->>'fixture_attributes_version' IS DISTINCT FROM '2'; UPDATE endpoint_entities SET attributes=attributes||'{"fixture_attributes_version":"2"}'::jsonb WHERE endpoint_id LIKE 'mac:00:10:%' AND attributes->>'fixture_attributes_version' IS DISTINCT FROM '2'`)
	return err
}
