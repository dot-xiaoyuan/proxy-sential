package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// upsertFactCurrent hydrates only devices with changed or naturally expired
// event-bus facts. Stream-only updates never repeat this aggregation.
func upsertFactCurrent(ctx context.Context, tx pgx.Tx, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO discovery_device_current_shadow(device_key,last_seen,fact_count,expired_fact_count,facts,updated_at)
SELECT f.device_key,max(f.observed_at),
       count(*) FILTER (WHERE f.withdrawn = FALSE AND (f.valid_until IS NULL OR f.valid_until > now()))::int,
       count(*) FILTER (WHERE f.withdrawn = TRUE OR (f.valid_until IS NOT NULL AND f.valid_until <= now()))::int,
       coalesce(jsonb_object_agg(f.fact_key, jsonb_build_object(
           'event_id',f.event_id,'protocol',f.protocol,'ip',f.ip,'mac',f.mac,
           'observed_at',f.observed_at,'valid_until',f.valid_until,
           'withdrawn',f.withdrawn,'content_hash',f.content_hash,'version',f.version))
           FILTER (WHERE f.withdrawn = FALSE AND (f.valid_until IS NULL OR f.valid_until > now())), '{}'::jsonb),now()
FROM discovery_service_facts_shadow f
WHERE f.device_key=ANY($1::text[])
GROUP BY f.device_key
ON CONFLICT (device_key) DO UPDATE SET
 last_seen=GREATEST(discovery_device_current_shadow.last_seen,EXCLUDED.last_seen),
 fact_count=EXCLUDED.fact_count,
 expired_fact_count=EXCLUDED.expired_fact_count,
 facts=EXCLUDED.facts,
 document=CASE WHEN EXCLUDED.fact_count>0
   THEN discovery_device_current_shadow.document||'{"current":true}'::jsonb
   ELSE discovery_device_current_shadow.document END,
 updated_at=now()
WHERE discovery_device_current_shadow.last_seen<EXCLUDED.last_seen
   OR discovery_device_current_shadow.fact_count IS DISTINCT FROM EXCLUDED.fact_count
   OR discovery_device_current_shadow.expired_fact_count IS DISTINCT FROM EXCLUDED.expired_fact_count
   OR discovery_device_current_shadow.facts IS DISTINCT FROM EXCLUDED.facts
   OR (EXCLUDED.fact_count>0 AND discovery_device_current_shadow.document->>'current'='false')`, keys)
	if err != nil {
		return fmt.Errorf("aggregate device current facts: %w", err)
	}
	return nil
}

// A device without a currently valid event-bus fact uses compact stream facts
// for the ledger's evidence count and references. Limit aggregation to keys
// touched in this transaction, including natural fact expiry.
func upsertStreamFactCurrent(ctx context.Context, tx pgx.Tx, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE discovery_device_current_shadow c
SET facts=agg.facts,fact_count=agg.fact_count,expired_fact_count=agg.expired_count,updated_at=now()
FROM (
 SELECT f.device_key,
  coalesce(jsonb_object_agg(f.fact_key,jsonb_build_object(
   'event_id',f.event_key,'protocol',f.protocol,'ip',f.ip,'mac',f.mac,
   'observed_at',f.observed_at,'valid_until',f.valid_until,
   'withdrawn',f.withdrawn,'content_hash',f.semantic_hash,'version',f.revision))
   FILTER (WHERE f.withdrawn=FALSE AND f.valid_until>now()),'{}'::jsonb) AS facts,
  count(*) FILTER (WHERE f.withdrawn=FALSE AND f.valid_until>now())::int AS fact_count,
  count(*) FILTER (WHERE f.withdrawn=TRUE OR f.valid_until<=now())::int AS expired_count
 FROM unnest($1::text[]) AS requested(device_key)
 JOIN (SELECT DISTINCT epoch FROM stream_source_cutovers WHERE state='active') sc ON true
 JOIN LATERAL (
  SELECT f.device_key,f.fact_key,f.event_key,f.protocol,f.ip,f.mac,f.observed_at,
         f.valid_until,f.withdrawn,f.semantic_hash,f.revision
  FROM stream_discovery_facts f
  JOIN stream_discovery_device_state s ON s.epoch=f.epoch AND s.device_key=f.device_key
  WHERE f.epoch=sc.epoch AND f.device_key=requested.device_key AND f.scope_id=s.scope_id
  ORDER BY f.observed_at DESC,f.event_key DESC LIMIT 256
 ) f ON true
 GROUP BY f.device_key
) agg
WHERE c.device_key=agg.device_key
 AND NOT EXISTS(SELECT 1 FROM discovery_service_facts_shadow ef
   WHERE ef.device_key=c.device_key AND NOT ef.withdrawn
     AND (ef.valid_until IS NULL OR ef.valid_until>now()))
 AND (c.facts IS DISTINCT FROM agg.facts
   OR c.fact_count IS DISTINCT FROM agg.fact_count
   OR c.expired_fact_count IS DISTINCT FROM agg.expired_count)`, keys)
	if err != nil {
		return fmt.Errorf("aggregate stream-only current facts: %w", err)
	}
	return nil
}

// pruneChangedCurrent removes rows only for devices touched in this batch.
// A withdrawn fact alone cannot remove a device with an active stream state.
func pruneChangedCurrent(ctx context.Context, tx pgx.Tx, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `DELETE FROM discovery_device_current_shadow c
WHERE c.device_key=ANY($1::text[]) AND c.fact_count=0
AND NOT EXISTS (
 SELECT 1 FROM stream_discovery_device_state s
 JOIN stream_source_cutovers sc ON sc.epoch=s.epoch AND sc.state='active'
 WHERE s.device_key=c.device_key AND s.document->>'current'='true'
)`, keys)
	if err != nil {
		return fmt.Errorf("prune changed current devices: %w", err)
	}
	return nil
}
