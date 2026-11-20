SET LOCAL lock_timeout = '5s';

ALTER TABLE stream_shared_segment_receipts
 DROP CONSTRAINT stream_shared_segment_receipts_event_count_check,
 ADD CONSTRAINT stream_shared_segment_receipts_event_count_check
 CHECK (event_count BETWEEN 0 AND 2000) NOT VALID;

ALTER TABLE shared_gateway_observation_jobs ADD COLUMN source_epoch text NOT NULL DEFAULT '';
ALTER TABLE shared_capture_progress ADD COLUMN source_epoch text NOT NULL DEFAULT '';

CREATE INDEX stream_shared_segment_receipts_epoch_completed
 ON stream_shared_segment_receipts(epoch,completed_at DESC,segment_id);

CREATE TABLE stream_shared_source_runtime (
 sensor_id text NOT NULL,
 source_path text NOT NULL,
 epoch text NOT NULL,
 accepted_segment text NOT NULL DEFAULT '',
 accepted_at timestamptz,
 archived_segment text NOT NULL DEFAULT '',
 archived_at timestamptz,
 pending_segments integer NOT NULL DEFAULT 0,
 pending_bytes bigint NOT NULL DEFAULT 0,
 oldest_pending_at timestamptz,
 failed_segment text NOT NULL DEFAULT '',
 failed_stage text NOT NULL DEFAULT '',
 failed_at timestamptz,
 blocker text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,source_path,epoch)
);

-- A repair records only a locator and disposition. The ClickHouse body is
-- authoritative, including the original accepted_at and observation time.
CREATE TABLE stream_shared_packet_repairs (
 epoch text NOT NULL,
 event_key text NOT NULL,
 content_sha256 text NOT NULL CHECK (length(content_sha256)=64),
 accepted_at timestamptz NOT NULL,
 observed_at timestamptz NOT NULL,
 state text NOT NULL CHECK (state IN ('enqueued','expired_without_evaluation','already_enqueued')),
 repaired_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(epoch,event_key)
);

CREATE TABLE stream_shared_packet_repair_progress (
 epoch text PRIMARY KEY,
 indexed_at timestamptz NOT NULL,
 event_key text NOT NULL,
 content_sha256 text NOT NULL,
 complete boolean NOT NULL DEFAULT false
);
