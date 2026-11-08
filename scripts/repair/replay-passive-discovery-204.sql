-- Rewind only the 204 passive projection cursor after the event-time race.
-- Raw ClickHouse events and ingestion checkpoints remain unchanged. Replayed
-- observations use their existing idempotent keys; counters are cumulative.
\set ON_ERROR_STOP on
BEGIN;
INSERT INTO audit_logs(audit_id,actor,action,target,outcome)
SELECT 'audit-204-passive-replay-20261105','system-204-repair',
       'discovery.passive_cursor_replay','sensor:campus-204',
       jsonb_build_object('old_cursor_timestamp',cursor_timestamp,'old_cursor_event_id',cursor_event_id,
                          'replay_from',:'start_at','reason','late ARP arrived behind global event-time cursor')::text
FROM passive_discovery_state
WHERE sensor_id='campus-204' AND cursor_timestamp>:'start_at'::timestamptz;
UPDATE passive_discovery_state
SET cursor_timestamp=:'start_at'::timestamptz,cursor_event_id='',lease_owner='',
    lease_until='-infinity'::timestamptz,last_error='',updated_at=now()
WHERE sensor_id='campus-204' AND cursor_timestamp>:'start_at'::timestamptz;
COMMIT;
