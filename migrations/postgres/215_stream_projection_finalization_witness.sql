-- Preserve a source-position witness after all stream lanes finish and before
-- the local journal body is released. Historical rows stay NULL and cannot
-- establish archive coverage or authorize retention cleanup.
ALTER TABLE stream_projection_segments
 ADD COLUMN source_file_id text,
 ADD COLUMN source_start_offset bigint,
 ADD COLUMN source_end_offset bigint,
 ADD COLUMN lanes_finalized_at timestamptz;

-- NOT VALID avoids scanning the existing projection history during install.
-- PostgreSQL still enforces this constraint on every new or updated row.
ALTER TABLE stream_projection_segments
 ADD CONSTRAINT stream_projection_finalization_position CHECK (
  (source_file_id IS NULL AND source_start_offset IS NULL
   AND source_end_offset IS NULL AND lanes_finalized_at IS NULL)
  OR
  (source_file_id IS NOT NULL AND source_file_id <> ''
   AND source_start_offset IS NOT NULL AND source_start_offset >= 0
   AND source_end_offset IS NOT NULL AND source_end_offset > source_start_offset)
 ) NOT VALID;
