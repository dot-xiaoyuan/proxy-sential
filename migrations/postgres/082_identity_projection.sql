CREATE TABLE IF NOT EXISTS account_identity_session_projection (
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,
 session_id text NOT NULL,ip text NOT NULL,account_id text NOT NULL,confirmed_at timestamptz NOT NULL,
 document jsonb NOT NULL,PRIMARY KEY(source,sensor_id,campus_id,access_domain,session_id,ip)
);
CREATE INDEX IF NOT EXISTS account_identity_projection_account ON account_identity_session_projection(account_id,confirmed_at DESC);
CREATE TABLE IF NOT EXISTS account_identity_projection_sources (
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,
 observed_at timestamptz NOT NULL,PRIMARY KEY(source,sensor_id,campus_id,access_domain)
);
CREATE TABLE IF NOT EXISTS identity_snapshot_projection_jobs (
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,
 snapshot_id text NOT NULL,observed_at timestamptz NOT NULL,
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,snapshot_id)
);
CREATE OR REPLACE FUNCTION enqueue_identity_snapshot_projection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO identity_snapshot_projection_jobs VALUES(NEW.source,NEW.sensor_id,NEW.campus_id,NEW.access_domain,NEW.snapshot_id,NEW.observed_at) ON CONFLICT DO NOTHING;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_snapshot_projection_dirty AFTER INSERT ON identity_full_snapshots FOR EACH ROW EXECUTE FUNCTION enqueue_identity_snapshot_projection();
INSERT INTO identity_snapshot_projection_jobs SELECT source,sensor_id,campus_id,access_domain,snapshot_id,observed_at FROM identity_full_snapshots WHERE observed_at>=now()-interval '7 days' ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS identity_materializer_cursors (
 sensor_id text NOT NULL,phase text NOT NULL,cursor_at timestamptz NOT NULL,event_id text NOT NULL DEFAULT '',
 cutover_at timestamptz NOT NULL,processed_events bigint NOT NULL DEFAULT 0,
 last_success_at timestamptz,last_error text NOT NULL DEFAULT '',PRIMARY KEY(sensor_id,phase)
);
ALTER TABLE srun4k_integrations ADD COLUMN IF NOT EXISTS last_identity_poll_at timestamptz;
ALTER TABLE srun4k_integrations ADD COLUMN IF NOT EXISTS last_identity_event_at timestamptz;
