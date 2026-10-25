-- Additive, old workers remain readable. Deployment must stop old consumers
-- before starting leased consumers; an application rollback keeps these tables.
ALTER TABLE discovery_batch_work
 ADD COLUMN lease_token text NOT NULL DEFAULT '',
 ADD COLUMN lease_until timestamptz NOT NULL DEFAULT '-infinity',
 ADD COLUMN last_progress_at timestamptz,
 ADD COLUMN last_failure_at timestamptz,
 ADD COLUMN error_stage text NOT NULL DEFAULT '';

-- One bounded row per configured consumer/lane; overwritten every five seconds.
CREATE TABLE discovery_consumer_runtime (
 consumer_id text PRIMARY KEY, lane text NOT NULL, mode text NOT NULL,
 started_at timestamptz NOT NULL, heartbeat_at timestamptz NOT NULL,
 last_progress_at timestamptz, processed_events bigint NOT NULL DEFAULT 0,
 completed_segments bigint NOT NULL DEFAULT 0, timeout_failures bigint NOT NULL DEFAULT 0,
 retries bigint NOT NULL DEFAULT 0, events_per_second double precision NOT NULL DEFAULT 0, last_error_at timestamptz,
 last_error text NOT NULL DEFAULT '', error_stage text NOT NULL DEFAULT '',
 pause_reason text NOT NULL DEFAULT '',
 stages jsonb NOT NULL DEFAULT '{}'
);
-- Background aggregation only. HTTP reads at most three rows, never the queue.
CREATE TABLE discovery_pipeline_summary (
 lane text PRIMARY KEY, pending_batches bigint NOT NULL,
 eligible_batches bigint NOT NULL, failed_batches bigint NOT NULL,
 remaining_events bigint NOT NULL, oldest_pending_at timestamptz,
 last_progress_at timestamptz, updated_at timestamptz NOT NULL
);

-- Recovery identity survives the finite ClickHouse block deduplication window.
-- Retain at least one year. Retirement requires a matching durable projection
-- receipt and no case protection; unconfirmed records have no automatic TTL.
-- Same scoped key as discovery_event_receipts, one row per event revision.
CREATE TABLE discovery_normalized_receipts (
 sensor_id text NOT NULL, source_id text NOT NULL, event_id text NOT NULL,
 revision bigint NOT NULL, content_hash text NOT NULL,
 first_attempt_at timestamptz NOT NULL DEFAULT now(),
 resolve_after timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z',
 verified_at timestamptz,
 last_query_id text NOT NULL DEFAULT '',
 confirmed_at timestamptz,
 confirmation_uncertain boolean NOT NULL DEFAULT true,
 PRIMARY KEY(sensor_id,source_id,event_id,revision)
);
-- An immutable manifest records every queue move, without resetting timestamps.
CREATE TABLE discovery_recovery_manifest (
 recovery_id text NOT NULL, batch_id text NOT NULL REFERENCES discovery_batch_work(batch_id),
 cutoff_at timestamptz NOT NULL, original_lane text NOT NULL,
 original_offset integer NOT NULL, original_created_at timestamptz NOT NULL,
 original_error text NOT NULL, moved_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(recovery_id,batch_id)
);
CREATE INDEX discovery_normalized_receipt_retirement ON discovery_normalized_receipts(first_attempt_at)
 WHERE verified_at IS NOT NULL;
CREATE INDEX discovery_case_evidence_identity ON discovery_case_evidence_v2(sensor_id,source_id,event_id,revision);

-- Per-event latency origin, never reset by a retry. Unknown historical storage
-- acknowledgment is conservatively bounded by original batch admission.
ALTER TABLE discovery_event_receipts
 ADD COLUMN standard_stored_at timestamptz,
 ADD COLUMN storage_time_uncertain boolean NOT NULL DEFAULT true;

-- Preserve the old DHCP consumer's last observed time; migration is not a heartbeat.
INSERT INTO discovery_consumer_runtime(consumer_id,lane,mode,started_at,heartbeat_at,last_progress_at,processed_events,last_error)
 SELECT sensor_id||'/dhcp','dhcp','legacy',updated_at,updated_at,last_success_at,processed_events,last_error FROM passive_discovery_state;
