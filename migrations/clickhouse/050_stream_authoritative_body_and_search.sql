-- Fresh-epoch authoritative body: each event is routed to only one table.
-- The fixed archive_month is persisted in the source segment before insert.
CREATE TABLE IF NOT EXISTS stream_event_body_short (
 archive_month UInt32,
 scope_id String,
 event_key String,
 content_sha256 FixedString(64),
 accepted_at DateTime64(6,'UTC'),
 observed_at DateTime64(6,'UTC'),
 first_archived_at DateTime64(6,'UTC') DEFAULT now64(6),
 source LowCardinality(String),
 source_path String,
 file_id String,
 start_offset Int64,
 end_offset Int64,
 parser_version String,
 raw_sha256 String,
 raw_segment_id String,
 body String
) ENGINE=MergeTree
PARTITION BY archive_month
ORDER BY (scope_id,event_key,content_sha256)
TTL toDateTime(first_archived_at)+INTERVAL 7 DAY DELETE
SETTINGS non_replicated_deduplication_window=1000;

CREATE TABLE IF NOT EXISTS stream_event_body_evidence (
 archive_month UInt32,
 scope_id String,
 event_key String,
 content_sha256 FixedString(64),
 accepted_at DateTime64(6,'UTC'),
 observed_at DateTime64(6,'UTC'),
 first_archived_at DateTime64(6,'UTC') DEFAULT now64(6),
 source LowCardinality(String),
 source_path String,
 file_id String,
 start_offset Int64,
 end_offset Int64,
 parser_version String,
 raw_sha256 String,
 raw_segment_id String,
 body String
) ENGINE=MergeTree
PARTITION BY archive_month
ORDER BY (scope_id,event_key,content_sha256)
TTL toDateTime(first_archived_at)+INTERVAL 1 YEAR DELETE
SETTINGS non_replicated_deduplication_window=1000;

-- Exact source bytes are stored once per segment, not copied into every event.
-- A segment containing necessary evidence retains its source bytes for a year.
CREATE TABLE IF NOT EXISTS stream_source_raw (
 archive_month UInt32,
 segment_id String,
 raw_sha256 FixedString(64),
 accepted_at DateTime64(6,'UTC'),
 first_archived_at DateTime64(6,'UTC') DEFAULT now64(6),
 retention_class LowCardinality(String),
 source LowCardinality(String),
 source_path String,
 file_id String,
 start_offset Int64,
 end_offset Int64,
 raw_base64 String
) ENGINE=MergeTree
PARTITION BY archive_month
ORDER BY (segment_id,raw_sha256)
TTL if(retention_class='evidence',addYears(toDateTime(first_archived_at),1),addDays(toDateTime(first_archived_at),7)) DELETE
SETTINGS non_replicated_deduplication_window=1000;

-- Typed lookup rows do not repeat any full event JSON. The body_ref contains
-- the immutable retention class, archive month, scope, key and content hash.
CREATE TABLE IF NOT EXISTS stream_event_search (
 scope_id String,
 protocol LowCardinality(String),
 observed_at DateTime64(6,'UTC'),
 event_key String,
 content_sha256 FixedString(64),
 archive_month UInt32,
 retention_class LowCardinality(String),
 indexed_at DateTime64(6,'UTC') DEFAULT now64(6),
 event_type LowCardinality(String),
 source LowCardinality(String),
 sensor_id String,
 subject_ip String,
 subject_mac String,
 src_ip String,
 dst_ip String,
 src_port UInt32,
 dst_port UInt32,
 body_ref String
) ENGINE=MergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (scope_id,protocol,observed_at,event_key)
TTL toDateTime(indexed_at)+toIntervalDay(if(retention_class='evidence',30,7)) DELETE
SETTINGS non_replicated_deduplication_window=1000;
