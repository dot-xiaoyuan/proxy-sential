-- New segments can use these tables after every reader understands body_layout=v2.
-- Existing bodies stay in the original tables; each new body is written once.
-- Smaller granules bound point-read amplification at the cost of more marks and
-- potentially more write/merge work. Measure both under real input before cutover.
CREATE TABLE IF NOT EXISTS stream_event_body_short_v2 (
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
SETTINGS index_granularity=512,non_replicated_deduplication_window=1000;

CREATE TABLE IF NOT EXISTS stream_event_body_evidence_v2 (
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
SETTINGS index_granularity=512,non_replicated_deduplication_window=1000;
