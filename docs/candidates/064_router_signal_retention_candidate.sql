-- CANDIDATE ONLY. Keep this outside migrations/clickhouse until a disposable
-- ClickHouse 25.9.2.1 test proves old parts survive their former TTL and the
-- automatic migration path has been reviewed. Body/raw TTLs precede index TTL.
-- materialize_ttl_after_modify is a per-query setting, not a MergeTree setting.

ALTER TABLE stream_event_body_short
MODIFY TTL toDateTime(first_archived_at) + INTERVAL 14 DAY DELETE
SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE stream_event_body_short_v2
MODIFY TTL toDateTime(first_archived_at) + INTERVAL 14 DAY DELETE
SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE stream_source_raw
MODIFY TTL if(retention_class = 'evidence',
              addYears(toDateTime(first_archived_at), 1),
              addDays(toDateTime(first_archived_at), 14)) DELETE
SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE stream_router_signal_index
MODIFY TTL if(retention_class = 'evidence',
              toDateTime(indexed_at) + INTERVAL 30 DAY,
              toDateTime(indexed_at) + INTERVAL 13 DAY) DELETE
SETTINGS materialize_ttl_after_modify = 0;
