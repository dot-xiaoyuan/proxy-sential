-- A narrow subject-ordered locator for shared-access evidence. The canonical
-- event body remains in stream_event_body_*; this table stores only its
-- immutable hash and reference. Readers must stay on stream_event_search until
-- the new index has been reconciled for their active window.
CREATE TABLE IF NOT EXISTS stream_shared_signal_subject_index (
 scope_id String,
 source LowCardinality(String),
 subject_key String,
 observed_at DateTime64(6,'UTC'),
 event_key String,
 content_sha256 FixedString(64),
 archive_month UInt32,
 retention_class LowCardinality(String),
 indexed_at DateTime64(6,'UTC'),
 protocol LowCardinality(String),
 sensor_id String,
 campus_id String,
 access_domain String,
 subject_ip String,
 subject_mac String,
 collector_instance_id String,
 body_ref String
) ENGINE=MergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (scope_id,source,subject_key,observed_at,event_key)
TTL toDateTime(indexed_at)+toIntervalDay(if(retention_class='evidence',30,7)) DELETE
SETTINGS index_granularity=512,non_replicated_deduplication_window=1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS stream_shared_signal_subject_index_mv
TO stream_shared_signal_subject_index AS
SELECT scope_id,source,
 if(source='handshake-sidecar',subject_ip,subject_mac) AS subject_key,
 observed_at,event_key,content_sha256,archive_month,retention_class,indexed_at,
 protocol,sensor_id,campus_id,access_domain,subject_ip,subject_mac,
 collector_instance_id,body_ref
FROM stream_event_search
WHERE (source='handshake-sidecar' AND protocol IN ('handshake','capture_coverage'))
 OR (source='packet-sidecar' AND protocol IN
    ('ieee1905_client_association','ieee1905_client_snapshot','capture_coverage'));
