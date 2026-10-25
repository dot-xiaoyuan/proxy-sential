-- A segment is queued once, after the selected short-lived risk features and
-- authoritative body have both been confirmed. No event body is copied here.
CREATE SEQUENCE risk_feature_dirty_generation;
CREATE TABLE risk_feature_segment_receipts (
 segment_id text PRIMARY KEY,
 segment_sha256 text NOT NULL CHECK(length(segment_sha256)=64),
 source_epoch text NOT NULL,
 accepted_at timestamptz NOT NULL,
 queued_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE risk_feature_dirty_subjects (
 sensor_id text NOT NULL,
 subject_type text NOT NULL CHECK(subject_type IN ('ip','account')),
 subject_id text NOT NULL,
 generation bigint NOT NULL,
 first_dirty_at timestamptz NOT NULL DEFAULT now(),
 last_dirty_at timestamptz NOT NULL DEFAULT now(),
 last_observed_at timestamptz NOT NULL,
 claim_until timestamptz,
 claimed_generation bigint,
 PRIMARY KEY(sensor_id,subject_type,subject_id)
);
CREATE INDEX risk_feature_dirty_claim_idx
 ON risk_feature_dirty_subjects(sensor_id,claim_until,last_dirty_at);
