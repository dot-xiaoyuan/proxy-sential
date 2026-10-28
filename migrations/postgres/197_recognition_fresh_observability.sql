-- Forward-only instrumentation. Old receipts and recognition jobs are not
-- rewritten or enqueued. The immutable cutoff excludes pre-upgrade acceptance.
INSERT INTO read_model_runtime_state(name,state,updated_at)
VALUES('recognition-fresh-cutoff',jsonb_build_object('generation','layered-v1','since',clock_timestamp()),now())
ON CONFLICT DO NOTHING;
ALTER TABLE stream_discovery_receipts
 ADD COLUMN recognition_input jsonb,
 ADD COLUMN recognition_status text NOT NULL DEFAULT '',
 ADD COLUMN recognition_check_after timestamptz,
 ADD COLUMN recognition_completed_at timestamptz,
 ADD COLUMN recognition_overdue boolean NOT NULL DEFAULT false,
 ADD COLUMN recognition_result jsonb;
CREATE INDEX stream_discovery_receipts_recognition_pending
 ON stream_discovery_receipts(recognition_check_after,accepted_at)
 WHERE recognition_status IN ('processing','unattributed');
CREATE INDEX stream_discovery_receipts_recognition_window
 ON stream_discovery_receipts(accepted_at)
 WHERE recognition_input IS NOT NULL;
ALTER TABLE endpoint_recognition_jobs ADD COLUMN processed_at timestamptz, ADD COLUMN timings jsonb;
-- These compact annotations follow the receipt's existing hot/archive lifecycle;
-- they do not contain raw events or create another history retention policy.
