-- Explicitly retire unprocessed discovery work from active scheduling while
-- retaining the original batch, event payload, error and processing offset.
ALTER TABLE discovery_batch_work DROP CONSTRAINT discovery_batch_work_lane_check;
ALTER TABLE discovery_batch_work ADD CONSTRAINT discovery_batch_work_lane_check
 CHECK (lane IN ('realtime','backfill','rules','cancelled'));

CREATE TABLE discovery_cancel_manifest (
 cancel_id text NOT NULL,
 batch_id text NOT NULL REFERENCES discovery_batch_work(batch_id),
 cutoff_at timestamptz NOT NULL,
 original_lane text NOT NULL,
 original_offset integer NOT NULL,
 original_created_at timestamptz NOT NULL,
 original_error text NOT NULL,
 remaining_events integer NOT NULL,
 cancelled_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cancel_id,batch_id),
 UNIQUE(batch_id)
);
