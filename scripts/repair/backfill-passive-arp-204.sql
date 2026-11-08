-- One-time, bounded 204 reconciliation. Pass a fixed start_at, cutoff and
-- numeric limit via psql -v. Raw observations are retained unchanged.
\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE arp_204_candidates ON COMMIT DROP AS
SELECT lower(data->>'mac') AS mac, min(observed_at) AS first_seen, max(observed_at) AS last_seen
FROM discovery_observations
WHERE origin='arp' AND source_id LIKE 'passive:campus-204:%'
  AND observed_at BETWEEN :'start_at'::timestamptz AND :'cutoff'::timestamptz
  AND lower(data->>'mac') ~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
GROUP BY lower(data->>'mac')
ORDER BY lower(data->>'mac')
LIMIT (:limit + 1);

-- Abort the entire transaction if the bounded window exceeds the stated
-- limit. A partial selection must never look like a completed backfill.
SELECT 1 / CASE WHEN count(*) <= :limit THEN 1 ELSE 0 END AS within_limit
FROM arp_204_candidates;

INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,identity_confidence,attributes)
SELECT 'mac:'||mac,mac,'endpoint',first_seen,last_seen,0.55,'{"identity_source":"passive_arp_sender"}'::jsonb
FROM arp_204_candidates
ON CONFLICT(endpoint_id) DO NOTHING;

WITH latest AS (
  SELECT DISTINCT ON (lower(o.data->>'mac')) o.id,o.valid_until,o.data,o.source_id,
         lower(o.data->>'mac') AS mac
  FROM discovery_observations o JOIN arp_204_candidates c ON c.mac=lower(o.data->>'mac')
  WHERE o.origin='arp' AND o.source_id LIKE 'passive:campus-204:%'
    AND o.observed_at BETWEEN :'start_at'::timestamptz AND :'cutoff'::timestamptz
  ORDER BY lower(o.data->>'mac'),o.observed_at DESC,o.id DESC
)
INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis)
SELECT l.id,e.endpoint_id,l.valid_until,
       jsonb_build_object('kind','passive_arp_sender_identity','source','204_bounded_backfill','sensor',l.data->>'node','ip',l.data->>'ip','mac',l.mac,'origin','arp')
FROM latest l JOIN endpoint_entities e ON e.endpoint_id='mac:'||l.mac
ON CONFLICT(observation_id) DO NOTHING;

INSERT INTO audit_logs(audit_id,actor,action,target,outcome)
SELECT 'audit-204-arp-candidates-20261105','system-204-backfill',
       'discovery.arp_candidate_backfill','sensor:campus-204',
       jsonb_build_object('start_at',:'start_at','cutoff',:'cutoff','limit',:limit,'selected_mac',count(*))::text
FROM arp_204_candidates
ON CONFLICT(audit_id) DO NOTHING;

SELECT count(*) AS selected_mac,
       count(*) FILTER (WHERE e.endpoint_id IS NOT NULL) AS represented_mac
FROM arp_204_candidates c LEFT JOIN endpoint_entities e ON e.endpoint_id='mac:'||c.mac;
COMMIT;
