-- A lease change can wake recognition only when a current stream fact actually
-- carries product evidence. The first stream generation left many association-
-- only facts with recognition_fields='{}'; waking their endpoints rewrites old
-- summaries without adding a new recognition signal.
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
        AND f.recognition_fields<>'{}'::jsonb
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
        AND f.recognition_fields<>'{}'::jsonb
        AND NOT f.withdrawn AND f.valid_until>now()
        AND f.observed_at>=lease_row.observed_at AND f.observed_at<lease_row.valid_until
    ) THEN
      PERFORM mark_endpoint_recognition_dirty(lease_row.endpoint_id);
    END IF;
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;
