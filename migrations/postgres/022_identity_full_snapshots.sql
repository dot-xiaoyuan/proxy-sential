CREATE TABLE IF NOT EXISTS identity_full_snapshots (
 source text NOT NULL, sensor_id text NOT NULL, campus_id text NOT NULL, access_domain text NOT NULL,
 snapshot_id text NOT NULL, observed_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 1 AND 86400),
 session_count integer NOT NULL CHECK(session_count>=0), content_sha256 text NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,snapshot_id),
 UNIQUE(source,sensor_id,campus_id,access_domain,observed_at)
);
