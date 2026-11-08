-- One bounded batch of historical ARP evidence links on sensor campus-204.
-- Invoke repeatedly with fixed cutoff and increasing batch number until
-- selected=0. Existing observations and endpoint facts are not rewritten.
\set ON_ERROR_STOP on
BEGIN;
WITH todo AS MATERIALIZED (
  SELECT o.id,o.valid_until,o.data,lower(o.data->>'mac') AS mac
  FROM discovery_observations o
  LEFT JOIN discovery_identity_links l ON l.observation_id=o.id
  WHERE o.origin='arp' AND o.source_id LIKE 'passive:campus-204:%'
    AND o.observed_at<=:'cutoff'::timestamptz AND l.observation_id IS NULL
  ORDER BY o.observed_at,o.id
  LIMIT :limit
), inserted AS (
  INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis)
  SELECT t.id,e.endpoint_id,t.valid_until,
         jsonb_build_object('kind','passive_arp_sender_identity','source','204_history_repair',
                            'sensor',t.data->>'node','ip',t.data->>'ip','mac',t.mac,'origin','arp')
  FROM todo t JOIN endpoint_entities e ON e.endpoint_id='mac:'||t.mac AND e.entity_role='endpoint'
  ON CONFLICT(observation_id) DO NOTHING
  RETURNING observation_id
)
SELECT (SELECT count(*) FROM todo) AS selected,(SELECT count(*) FROM inserted) AS inserted
\gset
INSERT INTO audit_logs(audit_id,actor,action,target,outcome)
VALUES ('audit-204-arp-history-20261105-'||:'batch','system-204-repair',
        'discovery.arp_history_link','sensor:campus-204',
        jsonb_build_object('cutoff',:'cutoff','limit',:limit,'batch',:'batch',
                           'selected',:selected,'inserted',:inserted)::text);
SELECT :selected AS selected,:inserted AS inserted;
COMMIT;
