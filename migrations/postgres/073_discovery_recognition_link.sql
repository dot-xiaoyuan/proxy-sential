-- Recompute terminal recognition when a reliable passive observation is linked.
CREATE OR REPLACE FUNCTION enqueue_discovery_link_recognition_job() RETURNS trigger AS $$
DECLARE target_id TEXT;
BEGIN
 FOR target_id IN
  SELECT DISTINCT changed.target_endpoint_id FROM (VALUES
   (CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.endpoint_id END),
   (CASE WHEN TG_OP='DELETE' THEN NULL ELSE NEW.endpoint_id END)
  ) AS changed(target_endpoint_id)
  WHERE changed.target_endpoint_id IS NOT NULL AND changed.target_endpoint_id<>''
 LOOP
  INSERT INTO endpoint_recognition_jobs(endpoint_id)
  VALUES(target_id)
  ON CONFLICT(endpoint_id) DO UPDATE SET
   dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
   not_before=LEAST(endpoint_recognition_jobs.not_before,now()),updated_at=now();
 END LOOP;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS endpoint_recognition_discovery_link_dirty ON discovery_identity_links;
CREATE TRIGGER endpoint_recognition_discovery_link_dirty
AFTER INSERT OR UPDATE OR DELETE ON discovery_identity_links
FOR EACH ROW EXECUTE FUNCTION enqueue_discovery_link_recognition_job();

-- Existing current links are read-model input, not a rewrite of historical evidence.
INSERT INTO endpoint_recognition_jobs(endpoint_id)
SELECT DISTINCT endpoint_id
FROM discovery_identity_links
WHERE valid_until>now()
ON CONFLICT(endpoint_id) DO UPDATE SET
 dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
 not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
 updated_at=now();
