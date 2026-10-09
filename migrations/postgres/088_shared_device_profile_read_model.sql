-- Durable shared/network device profiles. Source writes only enqueue compact
-- identity keys; all joins and projection work run in the recognition worker.
CREATE TABLE IF NOT EXISTS shared_device_profile_runtime (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 cutover_at timestamptz NOT NULL DEFAULT now(),
 last_success_at timestamptz,
 last_error text NOT NULL DEFAULT '',
 processed_jobs bigint NOT NULL DEFAULT 0,
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO shared_device_profile_runtime(singleton) VALUES(true) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS shared_device_profiles (
 profile_id text PRIMARY KEY,
 sensor_id text NOT NULL,
 campus_id text NOT NULL DEFAULT '',
 endpoint_id text NOT NULL DEFAULT '',
 mac text NOT NULL DEFAULT '',
 primary_ip inet,
 vlan text NOT NULL DEFAULT '',
 display_name text NOT NULL DEFAULT '',
 role text NOT NULL DEFAULT '',
 brand text NOT NULL DEFAULT '',
 model text NOT NULL DEFAULT '',
 recognition_status text NOT NULL DEFAULT 'reference',
 confidence integer NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
 identity_conflict boolean NOT NULL DEFAULT false,
 latest_account_id text NOT NULL DEFAULT '',
 latest_account_at timestamptz,
 latest_account_active boolean NOT NULL DEFAULT false,
 latest_account_match_basis text NOT NULL DEFAULT '',
 account_conflict boolean NOT NULL DEFAULT false,
 identity_current boolean NOT NULL DEFAULT false,
 identity_at timestamptz NOT NULL,
 identity_expires_at timestamptz NOT NULL,
 current_shared boolean NOT NULL DEFAULT false,
 shared_confidence integer NOT NULL DEFAULT 0,
 last_shared_at timestamptz,
 last_observed_at timestamptz NOT NULL,
 first_seen timestamptz NOT NULL,
 source_rule_version text NOT NULL DEFAULT '',
 source_assessment_id text NOT NULL DEFAULT '',
 source_evidence_id text NOT NULL DEFAULT '',
 source_shared_observation_id text NOT NULL DEFAULT '',
 address_state text NOT NULL DEFAULT 'unbound',
 address_only boolean NOT NULL DEFAULT false,
 list_item jsonb NOT NULL DEFAULT '{}'::jsonb,
 next_transition_at timestamptz,
 merged_into_profile_id text REFERENCES shared_device_profiles(profile_id),
 materialized_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shared_device_profiles_page
 ON shared_device_profiles(last_observed_at DESC,profile_id) WHERE merged_into_profile_id IS NULL;
CREATE INDEX IF NOT EXISTS shared_device_profiles_sensor_page
 ON shared_device_profiles(sensor_id,last_observed_at DESC,profile_id) WHERE merged_into_profile_id IS NULL;
CREATE INDEX IF NOT EXISTS shared_device_profiles_role
 ON shared_device_profiles(role,last_observed_at DESC) WHERE merged_into_profile_id IS NULL;
CREATE INDEX IF NOT EXISTS shared_device_profiles_status
 ON shared_device_profiles(recognition_status,last_observed_at DESC) WHERE merged_into_profile_id IS NULL;
CREATE INDEX IF NOT EXISTS shared_device_profiles_shared
 ON shared_device_profiles(current_shared,last_observed_at DESC) WHERE merged_into_profile_id IS NULL;
CREATE INDEX IF NOT EXISTS shared_device_profiles_account_conflict
 ON shared_device_profiles(account_conflict,last_observed_at DESC) WHERE merged_into_profile_id IS NULL;
CREATE INDEX IF NOT EXISTS shared_device_profiles_ip ON shared_device_profiles(sensor_id,primary_ip);
CREATE INDEX IF NOT EXISTS shared_device_profiles_mac ON shared_device_profiles(sensor_id,(lower(mac)));
CREATE INDEX IF NOT EXISTS shared_device_profiles_endpoint ON shared_device_profiles(endpoint_id) WHERE endpoint_id<>'';

CREATE TABLE IF NOT EXISTS shared_device_profile_keys (
 sensor_id text NOT NULL,
 campus_id text NOT NULL DEFAULT '',
 key_type text NOT NULL CHECK(key_type IN('endpoint','mac','address')),
 key_value text NOT NULL,
 profile_id text NOT NULL REFERENCES shared_device_profiles(profile_id) ON DELETE CASCADE,
 reliable boolean NOT NULL DEFAULT false,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 PRIMARY KEY(sensor_id,campus_id,key_type,key_value)
);
CREATE INDEX IF NOT EXISTS shared_device_profile_keys_profile
 ON shared_device_profile_keys(profile_id,key_type,last_seen DESC);

CREATE TABLE IF NOT EXISTS shared_device_profile_history (
 history_id bigserial PRIMARY KEY,
 profile_id text NOT NULL REFERENCES shared_device_profiles(profile_id) ON DELETE CASCADE,
 change_kind text NOT NULL,
 observed_at timestamptz NOT NULL,
 source_id text NOT NULL DEFAULT '',
 payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shared_device_profile_history_timeline
 ON shared_device_profile_history(profile_id,observed_at DESC,history_id DESC);
CREATE INDEX IF NOT EXISTS shared_device_profile_history_retention
 ON shared_device_profile_history(created_at);

CREATE TABLE IF NOT EXISTS shared_device_profile_jobs (
 subject_key text PRIMARY KEY,
 sensor_id text NOT NULL DEFAULT '',
 campus_id text NOT NULL DEFAULT '',
 endpoint_id text NOT NULL DEFAULT '',
 mac text NOT NULL DEFAULT '',
 ip inet,
 vlan text NOT NULL DEFAULT '',
 observed_at timestamptz NOT NULL,
 dirty_since timestamptz NOT NULL DEFAULT now(),
 dirty_generation bigint NOT NULL DEFAULT 1,
 processed_generation bigint NOT NULL DEFAULT 0,
 not_before timestamptz NOT NULL DEFAULT now(),
 next_run_at timestamptz,
 attempts integer NOT NULL DEFAULT 0,
 lease_owner text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shared_device_profile_jobs_ready
 ON shared_device_profile_jobs(not_before,updated_at)
 WHERE processed_generation<dirty_generation;
CREATE INDEX IF NOT EXISTS shared_device_profile_jobs_due
 ON shared_device_profile_jobs(next_run_at) WHERE next_run_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS shared_device_profile_lease_endpoint
 ON device_address_leases(sensor_id,endpoint_id,observed_at DESC,event_id DESC);
CREATE INDEX IF NOT EXISTS shared_device_profile_router_mac
 ON router_assessments((regexp_replace(lower(mac),'[^0-9a-f]','','g')),last_seen DESC) WHERE mac<>'';
CREATE INDEX IF NOT EXISTS shared_device_profile_discovery_mac
 ON discovery_observation_latest((regexp_replace(lower(coalesce(data->>'mac','')),'[^0-9a-f]','','g')),observed_at DESC)
 WHERE coalesce(data->>'mac','')<>'';
CREATE INDEX IF NOT EXISTS shared_device_profile_discovery_ip
 ON discovery_observation_latest((data->>'ip'),observed_at DESC) WHERE coalesce(data->>'ip','')<>'';
CREATE INDEX IF NOT EXISTS shared_device_profile_session_endpoint_history
 ON account_sessions(endpoint_id,updated_at DESC) WHERE endpoint_id<>'';
CREATE INDEX IF NOT EXISTS shared_device_profile_session_mac_history
 ON account_sessions((regexp_replace(lower(mac),'[^0-9a-f]','','g')),updated_at DESC) WHERE mac<>'';
CREATE INDEX IF NOT EXISTS shared_device_profile_projection_endpoint_history
 ON account_identity_session_projection((document->>'endpoint_id'),confirmed_at DESC)
 WHERE coalesce(document->>'endpoint_id','')<>'';
CREATE INDEX IF NOT EXISTS shared_device_profile_projection_mac_history
 ON account_identity_session_projection((regexp_replace(lower(coalesce(document->>'mac','')),'[^0-9a-f]','','g')),confirmed_at DESC)
 WHERE coalesce(document->>'mac','')<>'';

CREATE OR REPLACE FUNCTION enqueue_shared_device_profile_job(
 p_sensor text,p_campus text,p_endpoint text,p_mac text,p_ip inet,p_vlan text,p_observed timestamptz
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE normalized_mac text; identity text; target_sensor text;
BEGIN
 IF p_observed IS NULL OR p_observed<(SELECT cutover_at FROM shared_device_profile_runtime WHERE singleton) THEN RETURN; END IF;
 normalized_mac := regexp_replace(lower(coalesce(p_mac,'')),'[^0-9a-f]','','g');
 target_sensor := coalesce(p_sensor,'');
 IF coalesce(p_endpoint,'')<>'' THEN identity := 'endpoint:'||p_endpoint;
 ELSIF normalized_mac<>'' THEN identity := 'mac:'||normalized_mac;
 ELSIF p_ip IS NOT NULL THEN identity := 'address:'||coalesce(p_campus,'')||':'||coalesce(p_vlan,'')||':'||host(p_ip);
 ELSE RETURN;
 END IF;
 INSERT INTO shared_device_profile_jobs(subject_key,sensor_id,campus_id,endpoint_id,mac,ip,vlan,observed_at)
 VALUES(target_sensor||':'||identity,target_sensor,coalesce(p_campus,''),coalesce(p_endpoint,''),coalesce(p_mac,''),p_ip,coalesce(p_vlan,''),p_observed)
 ON CONFLICT(subject_key) DO UPDATE SET
  sensor_id=CASE WHEN EXCLUDED.sensor_id<>'' THEN EXCLUDED.sensor_id ELSE shared_device_profile_jobs.sensor_id END,
  campus_id=CASE WHEN EXCLUDED.campus_id<>'' THEN EXCLUDED.campus_id ELSE shared_device_profile_jobs.campus_id END,
  endpoint_id=CASE WHEN EXCLUDED.endpoint_id<>'' THEN EXCLUDED.endpoint_id ELSE shared_device_profile_jobs.endpoint_id END,
  mac=CASE WHEN EXCLUDED.mac<>'' THEN EXCLUDED.mac ELSE shared_device_profile_jobs.mac END,
  ip=coalesce(EXCLUDED.ip,shared_device_profile_jobs.ip),
  vlan=CASE WHEN EXCLUDED.vlan<>'' THEN EXCLUDED.vlan ELSE shared_device_profile_jobs.vlan END,
  observed_at=greatest(shared_device_profile_jobs.observed_at,EXCLUDED.observed_at),
  dirty_since=CASE WHEN shared_device_profile_jobs.processed_generation>=shared_device_profile_jobs.dirty_generation THEN now() ELSE shared_device_profile_jobs.dirty_since END,
  dirty_generation=shared_device_profile_jobs.dirty_generation+1,
  not_before=least(shared_device_profile_jobs.not_before,now()),updated_at=now();
END $$;

CREATE OR REPLACE FUNCTION shared_device_profile_router_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE row_data router_assessments; BEGIN
 row_data := CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
 PERFORM enqueue_shared_device_profile_job(coalesce(row_data.assessment->>'sensor_id',''),'',row_data.endpoint_id,row_data.mac,row_data.ip,coalesce(row_data.vlans[1],''),row_data.last_seen);
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER shared_device_profile_router_dirty AFTER INSERT OR UPDATE OR DELETE ON router_assessments
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_router_dirty();

CREATE OR REPLACE FUNCTION shared_device_profile_discovery_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM enqueue_shared_device_profile_job(coalesce(NEW.data->>'node',NEW.data->'evidence'->'observer'->>'sensor_id',''),coalesce(NEW.data->>'site',''),coalesce((SELECT endpoint_id FROM discovery_identity_links WHERE observation_id=NEW.id),''),coalesce(NEW.data->>'mac',''),nullif(NEW.data->>'ip','')::inet,coalesce(NEW.data->>'vlan',''),NEW.observed_at);
 RETURN NEW;
END $$;
CREATE TRIGGER shared_device_profile_discovery_dirty AFTER INSERT OR UPDATE ON discovery_observation_latest
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_discovery_dirty();

CREATE OR REPLACE FUNCTION shared_device_profile_discovery_link_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE row_data discovery_identity_links; observation discovery_observations;
BEGIN
 row_data := CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
 SELECT * INTO observation FROM discovery_observations WHERE id=row_data.observation_id;
 IF FOUND THEN
  PERFORM enqueue_shared_device_profile_job(coalesce(observation.data->>'node',observation.data->'evidence'->'observer'->>'sensor_id',''),coalesce(observation.data->>'site',''),row_data.endpoint_id,coalesce(observation.data->>'mac',''),nullif(observation.data->>'ip','')::inet,coalesce(observation.data->>'vlan',''),observation.observed_at);
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER shared_device_profile_discovery_link_dirty AFTER INSERT OR UPDATE OR DELETE ON discovery_identity_links
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_discovery_link_dirty();

CREATE OR REPLACE FUNCTION shared_device_profile_endpoint_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM enqueue_shared_device_profile_job('', '', NEW.endpoint_id, NEW.primary_mac, nullif(NEW.current_ip,'')::inet, '', NEW.updated_at);
 RETURN NEW;
END $$;
CREATE TRIGGER shared_device_profile_endpoint_dirty AFTER INSERT OR UPDATE ON endpoint_recognition_summary
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_endpoint_dirty();

CREATE OR REPLACE FUNCTION shared_device_profile_account_projection_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM enqueue_shared_device_profile_job(NEW.sensor_id,NEW.campus_id,coalesce(NEW.document->>'endpoint_id',''),coalesce(NEW.document->>'mac',''),nullif(NEW.ip,'')::inet,coalesce(NEW.document->>'vlan',''),NEW.confirmed_at);
 RETURN NEW;
END $$;
CREATE TRIGGER shared_device_profile_account_projection_dirty AFTER INSERT OR UPDATE ON account_identity_session_projection
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_account_projection_dirty();

CREATE OR REPLACE FUNCTION shared_device_profile_session_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE row_data account_sessions; BEGIN
 row_data := CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
 PERFORM enqueue_shared_device_profile_job('', '',coalesce(row_data.endpoint_id,''),coalesce(row_data.mac,''),row_data.ip,coalesce(row_data.vlan,''),row_data.updated_at);
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER shared_device_profile_session_dirty AFTER INSERT OR UPDATE OR DELETE ON account_sessions
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_session_dirty();

CREATE OR REPLACE FUNCTION shared_device_profile_lease_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM enqueue_shared_device_profile_job(NEW.sensor_id,NEW.campus_id,NEW.endpoint_id,'',NEW.ip,'',NEW.observed_at);
 PERFORM enqueue_shared_device_profile_job(NEW.sensor_id,NEW.campus_id,'','',NEW.ip,'',NEW.observed_at);
 RETURN NEW;
END $$;
CREATE TRIGGER shared_device_profile_lease_dirty AFTER INSERT OR UPDATE ON device_address_leases
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_lease_dirty();

CREATE OR REPLACE FUNCTION shared_device_profile_shared_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE row_data shared_behavior_observations; BEGIN
 row_data := CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
 PERFORM enqueue_shared_device_profile_job(row_data.sensor_id,row_data.campus_id,row_data.endpoint_id,'',row_data.ip,'',row_data.last_seen);
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER shared_device_profile_shared_dirty AFTER INSERT OR UPDATE OR DELETE ON shared_behavior_observations
 FOR EACH ROW EXECUTE FUNCTION shared_device_profile_shared_dirty();
