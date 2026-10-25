-- Add the source-owned identity scope to the existing body-free search row.
-- Older search rows keep empty defaults and are excluded from the new reader.
ALTER TABLE stream_event_search ADD COLUMN IF NOT EXISTS campus_id String;
ALTER TABLE stream_event_search ADD COLUMN IF NOT EXISTS access_domain String;
ALTER TABLE stream_event_search ADD COLUMN IF NOT EXISTS collector_instance_id String;

-- Shared readers use stream_event_search itself: this prevents a second
-- materialized-view acknowledgement dependency on ClickHouse 25.9. The
-- source-owned scope and time window stay mandatory in each bounded query.
-- The 30-day shared-decision archiver still needs the narrow locators used
-- by its bounded reader after the threshold. Packet-sidecar also emits
-- unrelated device and topology signals; those keep the ordinary search TTL.
ALTER TABLE stream_event_search MODIFY TTL
 if((source='handshake-sidecar' AND protocol IN ('handshake','capture_coverage'))
    OR (source='packet-sidecar' AND protocol IN ('ieee1905_client_association','ieee1905_client_snapshot','capture_coverage')),
    addYears(toDateTime(indexed_at),1),
    toDateTime(indexed_at)+toIntervalDay(if(retention_class='evidence',30,7))) DELETE;
