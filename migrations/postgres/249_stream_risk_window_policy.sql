-- The incremental worker registers its actual evidence window. Producers may
-- omit an expired packet-only wake only while this lease is valid. The safe
-- skip horizon never shrinks, so a later wider worker cannot silently adopt
-- observations that were previously omitted from the dirty queue.
CREATE TABLE stream_risk_window_policies (
 sensor_id text PRIMARY KEY,
 active_window_seconds integer NOT NULL CHECK(active_window_seconds BETWEEN 1 AND 604800),
 safe_skip_seconds integer NOT NULL CHECK(safe_skip_seconds BETWEEN 1 AND 604800),
 lease_until timestamptz NOT NULL,
 registered_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(active_window_seconds<=safe_skip_seconds)
);

-- A skipped wake is an audited queue decision, not a missing source event.
-- The segment body and risk feature are confirmed before this receipt is made.
ALTER TABLE risk_feature_segment_receipts
 ADD COLUMN skipped_old_subjects integer NOT NULL DEFAULT 0 CHECK(skipped_old_subjects>=0),
 ADD COLUMN skipped_old_max_window_seconds integer CHECK(skipped_old_max_window_seconds BETWEEN 1 AND 604800);
