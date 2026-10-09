-- Existing deployments may have advanced beyond SNMP rows backfilled into the
-- bounded ClickHouse router stream. Rewind only the router recognition cursor;
-- evidence upserts remain idempotent and no source data is removed.
UPDATE router_recognition_state
SET cursor_timestamp=LEAST(COALESCE(cursor_timestamp,now()),now()-interval '24 hours'),
    cursor_event_id='',lease_owner='',lease_until='-infinity',last_error='',updated_at=now()
WHERE singleton
  AND NOT EXISTS (
      SELECT 1
      FROM router_evidence_facts
      WHERE source_family='snmp_management'
  );
