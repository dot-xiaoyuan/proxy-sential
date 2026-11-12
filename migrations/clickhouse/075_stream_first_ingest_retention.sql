-- The durable journal fixes accepted_at before a source cursor advances.
-- Replays retain this timestamp; first_archived_at/indexed_at do not.
-- Existing rows keep their recorded acceptance time. Legacy search rows have
-- no source acceptance column, so the old indexed_at is an explicit fallback.
-- Do not enqueue whole-table TTL materialization on this already loaded node.
-- Old evidence parts retain their previous later archive-based expiry until a
-- separately verified, bounded part/partition maintenance pass.
ALTER TABLE stream_event_body_short
MODIFY TTL toDateTime(accepted_at) + INTERVAL 7 DAY DELETE SETTINGS materialize_ttl_after_modify=0;

ALTER TABLE stream_event_body_evidence
MODIFY TTL addYears(toDateTime(accepted_at),1) DELETE SETTINGS materialize_ttl_after_modify=0;

ALTER TABLE stream_event_body_short_v2
MODIFY TTL toDateTime(accepted_at) + INTERVAL 7 DAY DELETE SETTINGS materialize_ttl_after_modify=0;

ALTER TABLE stream_event_body_evidence_v2
MODIFY TTL addYears(toDateTime(accepted_at),1) DELETE SETTINGS materialize_ttl_after_modify=0;

ALTER TABLE stream_source_raw
MODIFY TTL if(retention_class='evidence',addYears(toDateTime(accepted_at),1),addDays(toDateTime(accepted_at),7)) DELETE SETTINGS materialize_ttl_after_modify=0;

ALTER TABLE stream_event_search
ADD COLUMN IF NOT EXISTS first_ingested_at DateTime64(6,'UTC') DEFAULT indexed_at;

-- Shared-access evidence keeps the existing one-year lookup exception.
ALTER TABLE stream_event_search
MODIFY TTL if((source='handshake-sidecar' AND protocol IN ('handshake','capture_coverage'))
    OR (source='packet-sidecar' AND protocol IN ('ieee1905_client_association','ieee1905_client_snapshot','capture_coverage')),
    addYears(toDateTime(first_ingested_at),1),
    toDateTime(first_ingested_at)+toIntervalDay(if(retention_class='evidence',30,7))) DELETE SETTINGS materialize_ttl_after_modify=0;
