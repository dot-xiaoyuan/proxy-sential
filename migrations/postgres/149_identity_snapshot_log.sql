-- Metadata of every committed complete snapshot. Coverage intervals and the snapshot timeline are
-- read from this small log, so full snapshot documents no longer have to be retained to answer
-- "was the source reporting at time T" or "which snapshots confirmed a member".
-- projected marks snapshots whose membership reached account_identity_session_projection; only those
-- may count as confirmations, because a snapshot the projection skipped never applied its changes.
CREATE TABLE IF NOT EXISTS identity_snapshot_log (
 source text NOT NULL, sensor_id text NOT NULL, campus_id text NOT NULL, access_domain text NOT NULL,
 snapshot_id text NOT NULL, observed_at timestamptz NOT NULL, interval_seconds integer NOT NULL,
 session_count integer NOT NULL, content_sha256 text NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),
 projected boolean NOT NULL DEFAULT false,
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,snapshot_id)
);
CREATE INDEX IF NOT EXISTS identity_snapshot_log_scope_time
 ON identity_snapshot_log(source,sensor_id,campus_id,access_domain,observed_at);

INSERT INTO identity_snapshot_log(source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,interval_seconds,session_count,content_sha256,received_at,projected)
SELECT f.source,f.sensor_id,f.campus_id,f.access_domain,f.snapshot_id,f.observed_at,f.interval_seconds,f.session_count,f.content_sha256,f.received_at,
 COALESCE(f.observed_at<=src.observed_at,false)
FROM identity_full_snapshots f
LEFT JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain)
ON CONFLICT DO NOTHING;
