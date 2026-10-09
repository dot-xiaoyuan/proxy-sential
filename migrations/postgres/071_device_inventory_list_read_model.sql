ALTER TABLE endpoint_recognition_summary
  ADD COLUMN IF NOT EXISTS primary_mac TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS current_ip TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS current_account TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS current_access_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS device_name TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS filter_brand TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS filter_os_family TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS ecosystem_hint TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS list_item JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE endpoint_recognition_summary
SET primary_mac=coalesce(summary->>'primary_mac',''),
    current_ip=coalesce(summary->>'current_ip',''),
    current_account=coalesce(summary->>'current_account',''),
    current_access_id=coalesce(summary->>'current_access_id',''),
    device_name=coalesce(summary#>>'{device_name,value}',''),
    ecosystem_hint=coalesce(summary->>'ecosystem_hint',''),
    filter_brand=CASE
      WHEN coalesce((summary->>'recognition_conflict')::boolean,false) THEN
        CASE WHEN summary#>>'{brand_inference,status}'='inferred' THEN coalesce(nullif(summary#>>'{brand_inference,brand}',''),'unknown') ELSE 'unknown' END
      WHEN nullif(lower(summary->>'brand'),'unknown') IS NOT NULL AND coalesce(summary->>'brand','')<>'' THEN summary->>'brand'
      WHEN summary#>>'{brand_inference,status}'='inferred' THEN coalesce(nullif(summary#>>'{brand_inference,brand}',''),'unknown')
      WHEN coalesce(summary#>>'{brand_inference,status}','insufficient')='insufficient' THEN coalesce(nullif(summary#>>'{brand_reference,brand}',''),'unknown')
      ELSE 'unknown'
    END,
    filter_os_family=CASE
      WHEN coalesce((summary->>'recognition_conflict')::boolean,false) THEN 'unknown'
      WHEN coalesce(summary->>'os_family','')='' OR lower(summary->>'os_family')='unknown' THEN 'unknown'
      ELSE summary->>'os_family'
    END,
    list_item=jsonb_strip_nulls(jsonb_build_object(
      'endpoint_id',summary->'endpoint_id','primary_mac',summary->'primary_mac',
      'owner_account',summary->'owner_account','owner_name',summary->'owner_name',
      'current_account',summary->'current_account','current_ip',summary->'current_ip',
      'current_access_id',summary->'current_access_id','last_seen',summary->'last_seen',
      'device_name',summary->'device_name','brand_reference',summary->'brand_reference',
      'brand_inference',CASE WHEN jsonb_typeof(summary->'brand_inference')='object' THEN
        jsonb_strip_nulls(jsonb_build_object(
          'status',summary#>'{brand_inference,status}','brand',summary#>'{brand_inference,brand}',
          'confidence',summary#>'{brand_inference,confidence}'
        )) ELSE NULL END,'vendor',summary->'vendor','brand',summary->'brand',
      'model',summary->'model','device_type',summary->'device_type','os_family',summary->'os_family',
      'vendor_confidence',summary->'vendor_confidence','brand_confidence',summary->'brand_confidence',
      'model_confidence',summary->'model_confidence','device_type_confidence',summary->'device_type_confidence',
      'os_family_confidence',summary->'os_family_confidence','randomized_mac',summary->'randomized_mac',
      'recognition_conflict',summary->'recognition_conflict'
    ));

CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_page
ON endpoint_recognition_summary(last_seen DESC NULLS LAST,endpoint_id);
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_filter_brand
ON endpoint_recognition_summary(lower(filter_brand),last_seen DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_filter_os
ON endpoint_recognition_summary(lower(filter_os_family),last_seen DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_current_ip
ON endpoint_recognition_summary(current_ip);
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_primary_mac
ON endpoint_recognition_summary(lower(primary_mac));
CREATE INDEX IF NOT EXISTS endpoint_recognition_jobs_pending
ON endpoint_recognition_jobs(updated_at) WHERE processed_generation<dirty_generation;

DROP TRIGGER IF EXISTS endpoint_recognition_note_dirty ON device_name_notes;
CREATE TRIGGER endpoint_recognition_note_dirty
AFTER INSERT OR UPDATE OR DELETE ON device_name_notes
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

DROP TRIGGER IF EXISTS endpoint_recognition_session_dirty ON account_sessions;
CREATE TRIGGER endpoint_recognition_session_dirty
AFTER INSERT OR UPDATE OR DELETE ON account_sessions
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

DROP TRIGGER IF EXISTS endpoint_recognition_ip_history_dirty ON identity_ip_mac_history;
CREATE TRIGGER endpoint_recognition_ip_history_dirty
AFTER INSERT OR UPDATE OR DELETE ON identity_ip_mac_history
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

DROP TRIGGER IF EXISTS endpoint_recognition_access_history_dirty ON identity_access_history;
CREATE TRIGGER endpoint_recognition_access_history_dirty
AFTER INSERT OR UPDATE OR DELETE ON identity_access_history
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

INSERT INTO endpoint_recognition_jobs(endpoint_id)
SELECT endpoint_id FROM endpoint_entities WHERE entity_role='endpoint'
ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=now();
