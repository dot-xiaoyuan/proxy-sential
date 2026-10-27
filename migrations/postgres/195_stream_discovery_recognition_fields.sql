-- Only allowlisted, bounded protocol fields are copied into the current fact.
-- The event body remains in the stream archive. Existing facts are deliberately
-- not rewritten or queued: this generation starts with fresh input.
ALTER TABLE stream_discovery_facts
  ADD COLUMN recognition_fields jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX stream_discovery_facts_recognition_mac
  ON stream_discovery_facts(lower(mac),observed_at DESC)
  WHERE mac<>'' AND NOT withdrawn;

-- An event-time lease can arrive after its discovery fact. Revisit only the
-- endpoint named by the changed lease, and only when a current compact fact
-- could actually use that association. No existing lease is replayed here.
CREATE OR REPLACE FUNCTION wake_stream_recognition_for_lease() RETURNS trigger AS $$
DECLARE lease_row device_address_leases%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    lease_row := OLD;
    IF lease_row.endpoint_id<>'' AND lease_row.ip IS NOT NULL AND EXISTS (
      SELECT 1 FROM stream_source_cutovers c
      JOIN stream_discovery_facts f ON f.epoch=c.epoch
      JOIN endpoint_entities e ON e.endpoint_id=lease_row.endpoint_id
      WHERE c.state='active' AND f.ip=host(lease_row.ip)
        AND f.sensor_id=lease_row.sensor_id AND f.site=lease_row.campus_id
        AND lower(f.mac)=lower(e.primary_mac) AND f.mac<>''
        AND NOT f.withdrawn AND f.valid_until>now()
        AND f.observed_at>=lease_row.observed_at AND f.observed_at<lease_row.valid_until
    ) THEN
      PERFORM mark_endpoint_recognition_dirty(lease_row.endpoint_id);
    END IF;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    lease_row := NEW;
    IF lease_row.endpoint_id<>'' AND lease_row.ip IS NOT NULL AND EXISTS (
      SELECT 1 FROM stream_source_cutovers c
      JOIN stream_discovery_facts f ON f.epoch=c.epoch
      JOIN endpoint_entities e ON e.endpoint_id=lease_row.endpoint_id
      WHERE c.state='active' AND f.ip=host(lease_row.ip)
        AND f.sensor_id=lease_row.sensor_id AND f.site=lease_row.campus_id
        AND lower(f.mac)=lower(e.primary_mac) AND f.mac<>''
        AND NOT f.withdrawn AND f.valid_until>now()
        AND f.observed_at>=lease_row.observed_at AND f.observed_at<lease_row.valid_until
    ) THEN
      PERFORM mark_endpoint_recognition_dirty(lease_row.endpoint_id);
    END IF;
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER stream_recognition_lease_dirty
AFTER INSERT OR UPDATE OR DELETE ON device_address_leases
FOR EACH ROW EXECUTE FUNCTION wake_stream_recognition_for_lease();
