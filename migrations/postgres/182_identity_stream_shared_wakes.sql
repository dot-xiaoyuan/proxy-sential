-- Fresh position facts keep the shared-observation reader IP-addressable.
-- The wake function is called once per committed fragment by the new writer;
-- installing this migration alone cannot wake jobs through an older reader.
CREATE INDEX identity_stream_policy_scope_ip_time
 ON identity_stream_policy_facts(scope_key,(session_data->>'ip'),observed_at);

CREATE FUNCTION shared_identity_stream_inet(value text) RETURNS inet
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
 RETURN value::inet;
EXCEPTION WHEN invalid_text_representation THEN
 RETURN NULL;
END $$;

CREATE FUNCTION shared_wake_identity_stream_batch(batch jsonb) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE wake_mode text;
BEGIN
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF wake_mode IN ('shadow','async') THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain,ip)
  SELECT DISTINCT 'identity_ip',wake_mode,
   COALESCE(r.session_data->>'source',''),COALESCE(r.session_data->>'sensor_id',''),
   COALESCE(r.session_data->>'campus_id',''),COALESCE(r.session_data->>'access_domain',''),
   shared_identity_stream_inet(r.session_data->>'ip')
  FROM jsonb_to_recordset(batch) r(session_data jsonb,observed_at timestamptz)
  JOIN shared_observation_jobs j ON j.ip=shared_identity_stream_inet(r.session_data->>'ip')
   AND NOT j.expired AND j.last_event_at>=now()-interval '1 hour'
   AND r.observed_at>=j.last_event_at-interval '10 minutes';
 END IF;
 IF wake_mode<>'async' THEN
  UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),
   last_dependency_at=clock_timestamp(),
   dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
  FROM (
   SELECT DISTINCT shared_identity_stream_inet(r.session_data->>'ip') AS ip,
    r.session_data->>'source' AS source,r.session_data->>'sensor_id' AS sensor_id,
    r.session_data->>'campus_id' AS campus_id,r.session_data->>'access_domain' AS access_domain,
    max(r.observed_at) AS observed_at
   FROM jsonb_to_recordset(batch) r(session_data jsonb,observed_at timestamptz)
   GROUP BY 1,2,3,4,5
  ) changed
  WHERE j.ip=changed.ip AND NOT j.expired
   AND changed.observed_at>=j.last_event_at-interval '10 minutes'
   AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active
    AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
    AND m.identity_source=changed.source AND m.identity_sensor_id=changed.sensor_id
    AND m.identity_campus_id=changed.campus_id AND m.identity_access_domain=changed.access_domain
    AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 END IF;
END $$;
