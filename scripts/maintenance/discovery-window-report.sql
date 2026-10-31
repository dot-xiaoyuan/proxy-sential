-- Read-only report for the fresh discovery collection window.
\echo 'window'
SELECT now() AS captured_at, min(last_seen) AS oldest_current, max(last_seen) AS newest_current,
       count(*) AS current_devices,
       count(*) FILTER (WHERE fact_count=0) AS no_facts,
       count(*) FILTER (WHERE document->>'current'='false') AS current_false,
       count(*) FILTER (WHERE document='{}'::jsonb) AS empty_documents
FROM discovery_device_current_shadow;
\echo 'protocol_counts'
SELECT p AS protocol,count(*) AS devices
FROM discovery_device_current_shadow,jsonb_array_elements_text(coalesce(document->'protocols','[]'::jsonb)) p
GROUP BY p ORDER BY devices DESC;
\echo 'capability_counts'
SELECT c AS capability,count(*) AS devices
FROM discovery_device_current_shadow,jsonb_array_elements_text(coalesce(document->'capabilities','[]'::jsonb)) c
GROUP BY c ORDER BY devices DESC;
\echo 'completeness'
SELECT 'missing_stream' AS metric,count(*) AS value
FROM stream_discovery_device_state s
WHERE s.document->>'current'='true'
  AND NOT EXISTS (SELECT 1 FROM discovery_device_current_shadow c WHERE c.device_key=s.device_key)
UNION ALL
SELECT 'stream_facts',count(*) FROM stream_discovery_facts
UNION ALL
SELECT 'stream_state',count(*) FROM stream_discovery_device_state;
