SET LOCAL lock_timeout = '5s';
-- Prebuild CONCURRENTLY on existing installations before applying migration.
DO $$ BEGIN
 IF to_regclass('identity_projection_open_scope_member') IS NULL THEN
  CREATE INDEX identity_projection_open_scope_member ON account_identity_session_projection(source,sensor_id,campus_id,access_domain,session_id,ip) WHERE COALESCE(document->>'ended_at','')='';
 ELSIF NOT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid='identity_projection_open_scope_member'::regclass AND indisvalid AND indisready) THEN
  RAISE EXCEPTION 'prebuilt identity projection index is invalid';
 END IF;
END $$;
-- Empty settings means legacy. Only one implementation may apply a scope.
CREATE TABLE identity_delta_settings (
 scope_key text PRIMARY KEY, mode text NOT NULL CHECK(mode IN ('legacy','shadow','delta')),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE identity_delta_runs (
 run_id bigserial PRIMARY KEY,scope_key text NOT NULL,
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,
 snapshot_id text NOT NULL,observed_at timestamptz NOT NULL,received_at timestamptz NOT NULL,
 capture_started_at timestamptz,interval_seconds integer NOT NULL,expected_members integer NOT NULL,
 state text NOT NULL DEFAULT 'receiving' CHECK(state IN ('receiving','validated','diffing','ready','applying','completed','failed')),
 member_cursor integer NOT NULL DEFAULT 0,diff_cursor text NOT NULL DEFAULT '',exit_cursor text NOT NULL DEFAULT '',
 exits_complete boolean NOT NULL DEFAULT false,batch_size integer NOT NULL DEFAULT 100,
 lease_owner text NOT NULL DEFAULT '',lease_until timestamptz,
 actual_writes bigint NOT NULL DEFAULT 0,changed_members bigint NOT NULL DEFAULT 0,applied_members bigint NOT NULL DEFAULT 0,
 started_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,cleaned_at timestamptz,last_error text NOT NULL DEFAULT '',
 UNIQUE(source,sensor_id,campus_id,access_domain,snapshot_id)
);
CREATE UNIQUE INDEX identity_delta_scope_active ON identity_delta_runs(scope_key) WHERE state<>'completed';
CREATE TABLE identity_delta_members (
 run_id bigint NOT NULL REFERENCES identity_delta_runs(run_id),ordinal integer NOT NULL,
 member_key text NOT NULL,session_id text NOT NULL,ip text NOT NULL,account_id text NOT NULL,
 fingerprint text NOT NULL,document jsonb NOT NULL,
 PRIMARY KEY(run_id,member_key),UNIQUE(run_id,ordinal)
);
CREATE INDEX identity_delta_members_ip ON identity_delta_members(run_id,ip,member_key);
CREATE TABLE identity_delta_changes (
 run_id bigint NOT NULL REFERENCES identity_delta_runs(run_id),member_key text NOT NULL,
 ip text NOT NULL,session_id text NOT NULL,kind text NOT NULL CHECK(kind IN ('upsert','end')),
 document jsonb NOT NULL,applied_at timestamptz,conflict boolean NOT NULL DEFAULT false,
 PRIMARY KEY(run_id,member_key)
);
CREATE INDEX identity_delta_changes_pending ON identity_delta_changes(run_id,ip,member_key) WHERE applied_at IS NULL;
CREATE TABLE identity_delta_notifications (
 notification_id bigserial PRIMARY KEY,run_id bigint NOT NULL,ip text NOT NULL,
 document jsonb NOT NULL,received_at timestamptz NOT NULL DEFAULT now(),processed_at timestamptz,
 UNIQUE(run_id,ip)
);
CREATE INDEX identity_delta_notifications_pending ON identity_delta_notifications(notification_id) WHERE processed_at IS NULL;
-- Preserve the previous interval before a session/IP is reused. These evidence
-- rows are never age-deleted before an archive receipt protects their content.
CREATE TABLE identity_projection_intervals (
 scope_key text NOT NULL,session_id text NOT NULL,ip text NOT NULL,
 interval_hash text NOT NULL,confirmed_at timestamptz NOT NULL,document jsonb NOT NULL,
 first_received_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(scope_key,session_id,ip,interval_hash)
);
CREATE INDEX identity_projection_intervals_lookup ON identity_projection_intervals(scope_key,ip,confirmed_at);
-- Delta transactions publish a durable notification themselves. Suppressing
-- this row trigger breaks the old lock cycle with realtime device writers.
CREATE OR REPLACE FUNCTION shared_device_profile_account_projection_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF current_setting('proxy_sentinel.identity_delta',true)='on' THEN RETURN NEW; END IF;
 PERFORM enqueue_shared_device_profile_job(NEW.sensor_id,NEW.campus_id,coalesce(NEW.document->>'endpoint_id',''),coalesce(NEW.document->>'mac',''),nullif(NEW.ip,'')::inet,coalesce(NEW.document->>'vlan',''),NEW.confirmed_at);
 RETURN NEW;
END $$;
-- Pending address responsibility is independent of snapshot completeness.
CREATE TABLE identity_inbox_ip_pending (
 batch_id text NOT NULL,scope_key text NOT NULL,ip text NOT NULL,
 first_event_at timestamptz NOT NULL,last_event_at timestamptz NOT NULL,accepted_at timestamptz NOT NULL,
 PRIMARY KEY(batch_id,ip)
);
CREATE INDEX identity_inbox_ip_pending_lookup ON identity_inbox_ip_pending(scope_key,ip,first_event_at);

ALTER TABLE identity_snapshot_uploads ADD COLUMN capture_started_at timestamptz;

CREATE INDEX identity_delta_cleanup ON identity_delta_runs(completed_at,run_id) WHERE state='completed' AND cleaned_at IS NULL;
