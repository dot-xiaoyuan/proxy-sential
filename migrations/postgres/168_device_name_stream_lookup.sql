SET LOCAL lock_timeout = '5s';
-- Prebuild concurrently on existing large installations. One index entry per
-- retained evidence; no copied JSON payload, cache or additional retention.
DO $$ BEGIN
 IF to_regclass('device_name_stream_latest') IS NULL THEN
  CREATE INDEX device_name_stream_latest ON device_name_evidence
   (endpoint_id,source,lower(value),sensor_id,coalesce(evidence->>'address',''),observed_at DESC,event_id DESC);
 ELSIF NOT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid='device_name_stream_latest'::regclass AND indisvalid AND indisready) THEN
  RAISE EXCEPTION 'prebuilt device name stream lookup index is invalid';
 END IF;
END $$;
