-- Original log record bytes, once per source batch and row digest. The
-- PostgreSQL membership ledger carries the potentially many observation IDs.
-- No automatic deletion before the reference/retention audit.
CREATE TABLE IF NOT EXISTS passive_discovery_raw_archive (
 batch_id String, row_hash FixedString(64), batch_hash FixedString(64),
 accepted_at DateTime64(6,'UTC'), raw_b64 String CODEC(ZSTD(3))
) ENGINE=MergeTree PARTITION BY toYYYYMM(accepted_at) ORDER BY (batch_id,row_hash);
