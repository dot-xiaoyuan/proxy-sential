-- Attribute physical bytes only for parts containing a single source.
-- Classify using source_path, without reading the archived event bodies.
SELECT
    multiIf(empty(k.sources), 'unclassified', arrayStringConcat(k.sources, '+')) AS sources,
    sum(p.bytes_on_disk) AS bytes
FROM (
    SELECT table AS tbl, name AS part, bytes_on_disk
    FROM system.parts
    WHERE database = 'proxy_sentinel' AND active
      AND table IN ('stream_event_body_short', 'stream_event_body_evidence',
                    'stream_event_body_short_v2', 'stream_event_body_evidence_v2')
) AS p
LEFT JOIN (
    SELECT _table AS tbl, _part AS part,
           arraySort(groupUniqArray(multiIf(
               source_path = '/opt/proxy-sentinel/data/device-signals/handshake.jsonl', 'handshake',
               source_path = '/opt/proxy-sentinel/data/device-signals/ttl.jsonl', 'packet',
               'other'))) AS sources
    FROM merge('proxy_sentinel', '^stream_event_body_(short|evidence)(_v2)?$')
    GROUP BY tbl, part
) AS k USING (tbl, part)
GROUP BY sources
ORDER BY sources
SETTINGS max_threads = 1, max_memory_usage = 134217728, max_execution_time = 30, join_use_nulls = 0
FORMAT JSONEachRow
