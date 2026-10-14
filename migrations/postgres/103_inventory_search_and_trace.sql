-- Schema only: backfill is resumable, bounded and performed by one worker.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE TABLE endpoint_inventory_lookup (
 endpoint_id text PRIMARY KEY, list_item jsonb NOT NULL, last_seen timestamptz,
 device_name text NOT NULL DEFAULT '', mac_key text NOT NULL DEFAULT '', current_ip inet,
 search_text text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX inventory_lookup_seen ON endpoint_inventory_lookup(last_seen DESC NULLS LAST,endpoint_id);
CREATE INDEX inventory_lookup_mac ON endpoint_inventory_lookup(mac_key);
CREATE INDEX inventory_lookup_ip ON endpoint_inventory_lookup(current_ip);
CREATE INDEX inventory_lookup_name ON endpoint_inventory_lookup USING gin(lower(device_name) gin_trgm_ops);
CREATE INDEX inventory_lookup_text ON endpoint_inventory_lookup USING gin(search_text gin_trgm_ops);
CREATE TABLE endpoint_inventory_accounts (
 endpoint_id text NOT NULL, account_id text NOT NULL, observed_at timestamptz NOT NULL,
 PRIMARY KEY(endpoint_id,account_id)
);
CREATE INDEX inventory_accounts_exact ON endpoint_inventory_accounts(account_id,endpoint_id);
CREATE TABLE endpoint_inventory_associations (
 endpoint_id text NOT NULL, kind text NOT NULL CHECK(kind IN ('account','ip','access')),
 value text NOT NULL, source text NOT NULL, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
 observation_count bigint NOT NULL, session_count bigint NOT NULL DEFAULT 0, confidence double precision NOT NULL, event_id text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(endpoint_id,kind,value,source)
);
CREATE INDEX inventory_associations_page ON endpoint_inventory_associations(endpoint_id,last_seen DESC,kind,value,source);
-- Points, not min/max occupancy spans: gaps must never become historical IP matches.
CREATE TABLE endpoint_inventory_ip_points (
 endpoint_id text NOT NULL, ip inet NOT NULL, observed_at timestamptz NOT NULL, source text NOT NULL,
 PRIMARY KEY(endpoint_id,ip,observed_at,source)
);
CREATE INDEX inventory_ip_points_exact ON endpoint_inventory_ip_points(ip,observed_at DESC,endpoint_id);
CREATE TABLE endpoint_inventory_sessions (
 endpoint_id text NOT NULL, source text NOT NULL, session_id text NOT NULL, ip inet NOT NULL,
 account_id text NOT NULL, started_at timestamptz NOT NULL, ended_at timestamptz,
 confirmed_at timestamptz NOT NULL, access_id text NOT NULL, dimensions jsonb NOT NULL,
 confidence double precision NOT NULL DEFAULT 0,
 interval_explicit boolean NOT NULL DEFAULT true,
 PRIMARY KEY(endpoint_id,source,session_id,ip)
);
CREATE INDEX inventory_sessions_ip ON endpoint_inventory_sessions(ip,started_at,endpoint_id);
CREATE INDEX inventory_sessions_dimensions ON endpoint_inventory_sessions USING gin(dimensions);
CREATE TABLE endpoint_inventory_projection_jobs (
 endpoint_id text PRIMARY KEY, dirty_generation bigint NOT NULL DEFAULT 1,
 processed_generation bigint NOT NULL DEFAULT 0, not_before timestamptz NOT NULL DEFAULT now(),
 lease_owner text NOT NULL DEFAULT '', lease_until timestamptz NOT NULL DEFAULT 'epoch', last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX inventory_projection_pending ON endpoint_inventory_projection_jobs(not_before,endpoint_id)
 WHERE processed_generation<dirty_generation;
CREATE INDEX inventory_projection_unprepared ON endpoint_inventory_projection_jobs(endpoint_id) WHERE processed_generation=0;
CREATE TABLE endpoint_inventory_projection_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), cursor text NOT NULL DEFAULT '',
 backfill_complete boolean NOT NULL DEFAULT false, ready boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(),
 last_error text NOT NULL DEFAULT ''
);
ALTER TABLE endpoint_inventory_projection_state ADD COLUMN snapshot_cursor jsonb NOT NULL DEFAULT '["","","","",""]';
ALTER TABLE endpoint_inventory_projection_state ADD COLUMN snapshot_backfill_complete boolean NOT NULL DEFAULT false;
INSERT INTO endpoint_inventory_projection_state(singleton) VALUES(true);
CREATE TABLE endpoint_inventory_snapshot_jobs (
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,snapshot_id text NOT NULL,
 event_cursor integer NOT NULL DEFAULT 0, processed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,snapshot_id)
);
CREATE INDEX inventory_snapshot_pending ON endpoint_inventory_snapshot_jobs(source,sensor_id,campus_id,access_domain,snapshot_id) WHERE NOT processed;
CREATE TABLE endpoint_inventory_snapshot_facts (
 record_id text PRIMARY KEY, endpoint_id text NOT NULL,account_id text NOT NULL,ip inet,access_id text NOT NULL,
 source text NOT NULL,observed_at timestamptz NOT NULL,confidence double precision NOT NULL,event_id text NOT NULL,
 snapshot_ref jsonb NOT NULL
);
CREATE INDEX inventory_snapshot_facts_endpoint ON endpoint_inventory_snapshot_facts(endpoint_id,observed_at DESC,record_id);
CREATE INDEX IF NOT EXISTS inventory_auth_snapshot_endpoint
 ON account_identity_session_projection((document->>'endpoint_id'));

-- Endpoint-scoped background/detail use only; never used by inventory list SQL.
CREATE VIEW endpoint_inventory_observation_facts AS
 SELECT endpoint_id,'ip'::text kind,host(ip) value,source,last_seen observed_at,event_id,
 identity_confidence confidence, 'ip:'||history_id::text record_id,first_seen
 FROM identity_ip_mac_history WHERE ip IS NOT NULL
 UNION ALL SELECT endpoint_id,'account',account_id,source,last_seen,event_id,identity_confidence,'ip:'||history_id::text,first_seen
 FROM identity_ip_mac_history h WHERE coalesce(account_id,'')<>'' AND NOT EXISTS(
 SELECT 1 FROM identity_access_history a WHERE a.event_id=h.event_id AND a.endpoint_id=h.endpoint_id AND a.account_id=h.account_id AND a.source=h.source AND a.last_seen>h.last_seen)
 UNION ALL SELECT endpoint_id,'access',access_id,source,last_seen,event_id,identity_confidence,'access:'||history_id::text,first_seen
 FROM identity_access_history WHERE access_id<>''
 UNION ALL SELECT endpoint_id,'account',account_id,source,last_seen,event_id,identity_confidence,'access:'||history_id::text,first_seen
 FROM identity_access_history a WHERE coalesce(account_id,'')<>'' AND NOT EXISTS(
 SELECT 1 FROM identity_ip_mac_history h WHERE h.event_id=a.event_id AND h.endpoint_id=a.endpoint_id AND h.account_id=a.account_id AND h.source=a.source AND h.last_seen>=a.last_seen)
 UNION ALL SELECT endpoint_id,v.kind,v.value,source,observed_at,event_id,confidence,'snapshot:'||record_id,observed_at
 FROM endpoint_inventory_snapshot_facts f CROSS JOIN LATERAL(VALUES('account',account_id),('ip',host(ip)),('access',access_id)) v(kind,value) WHERE coalesce(v.value,'')<>''
 AND NOT EXISTS(SELECT 1 FROM identity_ip_mac_history h WHERE h.event_id=f.event_id AND h.endpoint_id=f.endpoint_id AND h.source=f.source AND v.kind IN('account','ip'))
 AND NOT EXISTS(SELECT 1 FROM identity_access_history a WHERE a.event_id=f.event_id AND a.endpoint_id=f.endpoint_id AND a.source=f.source AND v.kind IN('account','access'));

CREATE FUNCTION enqueue_inventory_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO endpoint_inventory_snapshot_jobs(source,sensor_id,campus_id,access_domain,snapshot_id)
 VALUES(NEW.source,NEW.sensor_id,NEW.campus_id,NEW.access_domain,NEW.snapshot_id) ON CONFLICT DO NOTHING;
 RETURN NULL;
END $$;
CREATE TRIGGER inventory_snapshot_change AFTER INSERT ON identity_full_snapshots FOR EACH ROW EXECUTE FUNCTION enqueue_inventory_snapshot();

CREATE FUNCTION enqueue_inventory_projection_id(id text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF coalesce(id,'')='' THEN RETURN; END IF;
 INSERT INTO endpoint_inventory_projection_jobs(endpoint_id) VALUES(id)
 ON CONFLICT(endpoint_id) DO UPDATE SET dirty_generation=endpoint_inventory_projection_jobs.dirty_generation+1,
 not_before=now(),updated_at=now();
END $$;
CREATE FUNCTION enqueue_inventory_projection() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_id text; new_id text;
BEGIN
 IF TG_OP<>'INSERT' THEN
   old_id=CASE WHEN TG_TABLE_NAME='account_identity_session_projection' THEN to_jsonb(OLD)->'document'->>'endpoint_id' ELSE to_jsonb(OLD)->>'endpoint_id' END;
 END IF;
 IF TG_OP<>'DELETE' THEN
   new_id=CASE WHEN TG_TABLE_NAME='account_identity_session_projection' THEN to_jsonb(NEW)->'document'->>'endpoint_id' ELSE to_jsonb(NEW)->>'endpoint_id' END;
 END IF;
 PERFORM enqueue_inventory_projection_id(new_id);
 IF old_id IS DISTINCT FROM new_id THEN PERFORM enqueue_inventory_projection_id(old_id); END IF;
 RETURN NULL;
END $$;
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['endpoint_entities','endpoint_recognition_summary','device_name_notes',
 'identity_ip_mac_history','identity_access_history','account_sessions','account_identity_session_projection'] LOOP
 EXECUTE format('CREATE TRIGGER inventory_projection_change AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION enqueue_inventory_projection()',name);
 END LOOP;
END $$;
