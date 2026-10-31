-- Read-only discovery current-state completeness report.
-- Run with: docker exec -i proxy-sentinel-postgres psql -U proxy_sentinel -d proxy_sentinel -f -
\echo 'current_documents'
SELECT count(*) FROM discovery_device_current_shadow;
\echo 'stale_current_false'
SELECT count(*) FROM discovery_device_current_shadow WHERE document->>'current'='false';
\echo 'empty_documents'
SELECT count(*) FROM discovery_device_current_shadow WHERE fact_count=0 AND document='{}'::jsonb;
\echo 'stream_current_missing'
SELECT count(*) FROM stream_discovery_device_state s
WHERE s.document->>'current'='true'
  AND NOT EXISTS (SELECT 1 FROM discovery_device_current_shadow c WHERE c.device_key=s.device_key);
\echo 'no_fact_documents'
SELECT count(*) FROM discovery_device_current_shadow WHERE fact_count=0;
\echo 'window_counts'
SELECT '24h' AS window,count(*) FROM discovery_device_current_shadow WHERE last_seen>now()-interval '24 hours'
UNION ALL SELECT '7d',count(*) FROM discovery_device_current_shadow WHERE last_seen>now()-interval '7 days'
UNION ALL SELECT 'all',count(*) FROM discovery_device_current_shadow;
