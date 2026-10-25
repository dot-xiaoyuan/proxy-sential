-- A stale partial spool file may not be valid JSON, so its event count is
-- unknown. Retain an exact byte count and SHA-256 rather than omitting it.
ALTER TABLE stream_discard_manifest
 ADD COLUMN unprocessed_bytes bigint NOT NULL DEFAULT 0 CHECK(unprocessed_bytes>=0);
