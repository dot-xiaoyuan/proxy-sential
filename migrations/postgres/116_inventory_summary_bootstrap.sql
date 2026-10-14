-- Initial current-state availability is independent from historical association
-- completeness. Only already materialized recognition summaries are copied.
ALTER TABLE endpoint_inventory_projection_state
 ADD COLUMN summary_cursor text NOT NULL DEFAULT '',
 ADD COLUMN summary_complete boolean NOT NULL DEFAULT false;
