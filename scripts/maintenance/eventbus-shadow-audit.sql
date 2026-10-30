-- Read-only audit for the discovery event-bus shadow tables.
-- Run against the 184 proxy_sentinel database; this script writes nothing.
\echo '== device counts =='
SELECT 'old_state' AS source, count(*) AS devices FROM discovery_device_state_v2
UNION ALL
SELECT 'new_current', count(*) FROM discovery_device_current_shadow;

\echo '== freshness =='
SELECT 'old_state' AS source, max(last_seen) AS max_last_seen, max(updated_at) AS max_updated_at
FROM discovery_device_state_v2
UNION ALL
SELECT 'new_current', max(last_seen), max(updated_at) FROM discovery_device_current_shadow;

\echo '== device key overlap =='
SELECT count(*) AS overlap
FROM discovery_device_current_shadow n
JOIN discovery_device_state_v2 o USING (device_key);

\echo '== new-only devices =='
SELECT count(*) AS new_only
FROM discovery_device_current_shadow n
WHERE NOT EXISTS (SELECT 1 FROM discovery_device_state_v2 o WHERE o.device_key = n.device_key);

\echo '== new-only devices that old facts table still knows =='
SELECT count(*) AS new_only_with_old_facts
FROM discovery_device_current_shadow n
WHERE NOT EXISTS (SELECT 1 FROM discovery_device_state_v2 o WHERE o.device_key = n.device_key)
  AND EXISTS (SELECT 1 FROM discovery_service_facts_v2 f WHERE f.device_key = n.device_key);

\echo '== fact key overlap =='
SELECT count(*) AS overlap
FROM discovery_service_facts_shadow n
JOIN discovery_service_facts_v2 o USING (device_key, fact_key);

\echo '== overlapping facts with identical latest event/hash =='
SELECT count(*) AS same_event_hash
FROM discovery_service_facts_shadow n
JOIN discovery_service_facts_v2 o USING (device_key, fact_key)
WHERE n.event_id = o.event_id AND n.content_hash = o.content_hash;

\echo '== actual fresh read path vs event-bus shadow =='
SELECT count(DISTINCT s.device_key) AS active_fresh_devices
FROM stream_discovery_device_state s
WHERE EXISTS (SELECT 1 FROM stream_source_cutovers c WHERE c.epoch = s.epoch AND c.state = 'active');

SELECT count(*) AS shadow_devices FROM discovery_device_current_shadow;

SELECT count(DISTINCT n.device_key) AS overlap_devices
FROM discovery_device_current_shadow n
WHERE EXISTS (
  SELECT 1 FROM stream_discovery_device_state s
  JOIN stream_source_cutovers c ON c.epoch = s.epoch AND c.state = 'active'
  WHERE s.device_key = n.device_key
);

SELECT count(DISTINCT n.device_key) AS shadow_only_devices
FROM discovery_device_current_shadow n
WHERE NOT EXISTS (
  SELECT 1 FROM stream_discovery_device_state s
  JOIN stream_source_cutovers c ON c.epoch = s.epoch AND c.state = 'active'
  WHERE s.device_key = n.device_key
);
