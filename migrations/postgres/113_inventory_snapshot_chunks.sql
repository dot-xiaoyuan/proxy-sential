-- Resumable, temporary parsing output. Source snapshots remain the retry input.
ALTER TABLE endpoint_inventory_snapshot_jobs ADD COLUMN staged_count integer;
CREATE TABLE endpoint_inventory_snapshot_chunks (
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,snapshot_id text NOT NULL,
 start_offset integer NOT NULL,events jsonb NOT NULL,
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,snapshot_id,start_offset)
);
