-- Durable acceptance is deliberately separate from identity and export completion.
ALTER TABLE identity_ingest_batches ADD COLUMN protocol_version integer NOT NULL DEFAULT 1;
ALTER TABLE identity_ingest_batches ADD COLUMN scope_key text;
ALTER TABLE identity_ingest_batches ADD COLUMN content_sha256 text;
ALTER TABLE identity_ingest_batches ADD COLUMN accepted_at timestamptz;
ALTER TABLE identity_ingest_batches ADD COLUMN sequence bigint;
ALTER TABLE identity_ingest_batches ADD COLUMN processed_offset integer NOT NULL DEFAULT 0;
ALTER TABLE identity_ingest_batches ADD COLUMN export_state text NOT NULL DEFAULT 'legacy';
ALTER TABLE identity_ingest_batches ADD COLUMN export_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE identity_ingest_batches ADD COLUMN export_lease_until timestamptz;
ALTER TABLE identity_ingest_batches ADD COLUMN export_error text;
CREATE UNIQUE INDEX identity_inbox_sequence ON identity_ingest_batches(scope_key,sequence) WHERE protocol_version=2;
CREATE INDEX identity_inbox_pending ON identity_ingest_batches(scope_key,sequence) WHERE protocol_version=2 AND status<>'completed';
CREATE INDEX identity_inbox_export ON identity_ingest_batches(sensor_id,accepted_at) WHERE protocol_version=2 AND export_state<>'completed';
CREATE TABLE identity_pipeline_scopes (
 scope_key text PRIMARY KEY, source text NOT NULL, sensor_id text NOT NULL, campus_id text NOT NULL, access_domain text NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 accepted_sequence bigint NOT NULL DEFAULT 0, processed_sequence bigint NOT NULL DEFAULT 0,
 pending_records bigint NOT NULL DEFAULT 0 CHECK(pending_records>=0), export_pending_records bigint NOT NULL DEFAULT 0 CHECK(export_pending_records>=0),
 current_generation text NOT NULL DEFAULT 'initial', accounts bigint NOT NULL DEFAULT 0 CHECK(accounts>=0), sessions bigint NOT NULL DEFAULT 0 CHECK(sessions>=0),
 statistics_at timestamptz, oldest_pending_at timestamptz, processed_at timestamptz,
 lease_epoch bigint NOT NULL DEFAULT 0, lease_until timestamptz, heartbeat_at timestamptz, last_error text NOT NULL DEFAULT '',
 snapshot_id text NOT NULL DEFAULT '', snapshot_at timestamptz, calibration_state text NOT NULL DEFAULT 'pending', calibration_error text NOT NULL DEFAULT '',
 UNIQUE(source,sensor_id,campus_id,access_domain)
);
CREATE TABLE identity_current_addresses (
 scope_key text NOT NULL, generation text NOT NULL, session_id text NOT NULL, ip text NOT NULL, account_id text NOT NULL,
 observed_at timestamptz NOT NULL, active boolean NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(scope_key,generation,session_id,ip)
);
CREATE TABLE identity_session_refs (
 scope_key text NOT NULL, generation text NOT NULL, session_id text NOT NULL, account_id text NOT NULL,
 addresses bigint NOT NULL CHECK(addresses>=0), PRIMARY KEY(scope_key,generation,session_id)
);
CREATE TABLE identity_account_refs (
 scope_key text NOT NULL, generation text NOT NULL, account_id text NOT NULL,
 sessions bigint NOT NULL CHECK(sessions>=0), PRIMARY KEY(scope_key,generation,account_id)
);
CREATE TABLE identity_applied_events (
 scope_key text NOT NULL,event_id text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(scope_key,event_id)
);
-- Unfinished inbox rows have no age-based deletion. Receipts remain idempotent.
CREATE OR REPLACE FUNCTION identity_ref_delta(sk text, gen text, sid text, aid text, delta integer)
RETURNS integer[] LANGUAGE plpgsql AS $$
DECLARE before_addresses bigint; after_addresses bigint; before_sessions bigint; after_sessions bigint; sd integer := 0; ad integer := 0; existing_account text;
BEGIN
 SELECT addresses,account_id INTO before_addresses,existing_account FROM identity_session_refs WHERE scope_key=sk AND generation=gen AND session_id=sid FOR UPDATE;
 IF FOUND AND existing_account<>aid THEN RAISE EXCEPTION 'identity session account conflict'; END IF;
 before_addresses := COALESCE(before_addresses,0); after_addresses := before_addresses+delta;
 INSERT INTO identity_session_refs VALUES(sk,gen,sid,aid,after_addresses) ON CONFLICT(scope_key,generation,session_id) DO UPDATE SET addresses=EXCLUDED.addresses;
 IF before_addresses=0 AND after_addresses>0 THEN sd:=1; ELSIF before_addresses>0 AND after_addresses=0 THEN sd:=-1; END IF;
 IF sd<>0 THEN
  SELECT sessions INTO before_sessions FROM identity_account_refs WHERE scope_key=sk AND generation=gen AND account_id=aid FOR UPDATE;
  before_sessions:=COALESCE(before_sessions,0); after_sessions:=before_sessions+sd;
  INSERT INTO identity_account_refs VALUES(sk,gen,aid,after_sessions) ON CONFLICT(scope_key,generation,account_id) DO UPDATE SET sessions=EXCLUDED.sessions;
  IF before_sessions=0 AND after_sessions>0 THEN ad:=1; ELSIF before_sessions>0 AND after_sessions=0 THEN ad:=-1; END IF;
 END IF;
 RETURN ARRAY[ad,sd];
END $$;
CREATE OR REPLACE FUNCTION identity_apply_address(sk text,gen text,sid text,ip_address text,aid text,stamp timestamptz,is_active boolean,doc jsonb)
RETURNS integer[] LANGUAGE plpgsql AS $$
DECLARE old identity_current_addresses%ROWTYPE; result integer[] := ARRAY[0,0]; d integer[];
BEGIN
 SELECT * INTO old FROM identity_current_addresses WHERE scope_key=sk AND generation=gen AND session_id=sid AND ip=ip_address FOR UPDATE;
 IF FOUND AND (old.observed_at>stamp OR (old.observed_at=stamp AND (NOT old.active OR is_active))) THEN RETURN result; END IF;
 IF FOUND AND NOT old.active AND is_active AND COALESCE(doc->>'session_status','') NOT IN ('start','login','accounting-start','reconcile') THEN RETURN result; END IF;
 IF old.active THEN result:=identity_ref_delta(sk,gen,sid,old.account_id,-1); END IF;
 IF is_active THEN d:=identity_ref_delta(sk,gen,sid,aid,1);result:=ARRAY[result[1]+d[1],result[2]+d[2]]; END IF;
 INSERT INTO identity_current_addresses VALUES(sk,gen,sid,ip_address,aid,stamp,is_active,doc)
 ON CONFLICT(scope_key,generation,session_id,ip) DO UPDATE SET account_id=EXCLUDED.account_id,observed_at=EXCLUDED.observed_at,active=EXCLUDED.active,document=EXCLUDED.document;
 RETURN result;
END $$;
ALTER TABLE identity_bridge_runtime ADD COLUMN queue_sampled_at timestamptz;
ALTER TABLE identity_bridge_runtime ADD COLUMN queue_sample_error boolean NOT NULL DEFAULT true;
CREATE TABLE identity_binding_window_heads (
 kind text NOT NULL,binding_key text NOT NULL,event_id text NOT NULL,last_seen timestamptz NOT NULL,
 PRIMARY KEY(kind,binding_key)
);
ALTER TABLE identity_applied_events ADD COLUMN batch_sequence bigint NOT NULL DEFAULT 0;
ALTER TABLE identity_applied_events ADD COLUMN ordinal integer NOT NULL DEFAULT 0;
ALTER TABLE identity_applied_events ADD COLUMN observed_at timestamptz;
ALTER TABLE identity_applied_events ADD COLUMN document jsonb;
CREATE INDEX identity_applied_replay ON identity_applied_events(scope_key,batch_sequence,ordinal);
ALTER TABLE identity_pipeline_scopes ADD COLUMN calibration_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE identity_pipeline_scopes ADD COLUMN calibration_lease_until timestamptz;
CREATE TABLE identity_legacy_recovery_events (
 scope_key text NOT NULL,event_id text NOT NULL,import_batch_id text NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(scope_key,event_id)
);
CREATE INDEX identity_legacy_recovery_batch ON identity_legacy_recovery_events(import_batch_id);
ALTER TABLE identity_pipeline_scopes ADD COLUMN export_last_error text NOT NULL DEFAULT '';
ALTER TABLE identity_pipeline_scopes ADD COLUMN export_heartbeat_at timestamptz;
ALTER TABLE identity_pipeline_scopes ADD COLUMN export_completed_at timestamptz;
ALTER TABLE identity_bridge_runtime ADD COLUMN quarantine_queue bigint NOT NULL DEFAULT 0 CHECK(quarantine_queue>=0);
