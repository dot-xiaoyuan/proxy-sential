-- Auxiliary identity/address projections may refresh an existing shared-device
-- profile, but must not create one job per ordinary endpoint. A later router,
-- infrastructure or sharing source still reads the already stored context when
-- it creates the profile, so this preserves both event orders.
CREATE OR REPLACE FUNCTION enqueue_existing_shared_device_profile_identity_jobs(
 p_sensor text,p_campus text,p_endpoint text,p_mac text,p_observed timestamptz
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE candidate record; normalized_mac text;
BEGIN
 normalized_mac := regexp_replace(lower(coalesce(p_mac,'')),'[^0-9a-f]','','g');
 IF coalesce(p_endpoint,'')='' AND normalized_mac='' THEN RETURN; END IF;
 FOR candidate IN
  SELECT DISTINCT p.sensor_id,p.campus_id,p.endpoint_id,p.mac,p.primary_ip,p.vlan
  FROM shared_device_profiles p
  WHERE p.merged_into_profile_id IS NULL
   AND (coalesce(p_sensor,'')='' OR p.sensor_id=p_sensor)
   AND (coalesce(p_campus,'')='' OR p.campus_id=p_campus)
   AND ((coalesce(p_endpoint,'')<>'' AND p.endpoint_id=p_endpoint)
     OR (normalized_mac<>'' AND regexp_replace(lower(p.mac),'[^0-9a-f]','','g')=normalized_mac))
 LOOP
  PERFORM enqueue_shared_device_profile_job(candidate.sensor_id,candidate.campus_id,candidate.endpoint_id,
   candidate.mac,candidate.primary_ip,candidate.vlan,p_observed);
 END LOOP;
END $$;

CREATE OR REPLACE FUNCTION enqueue_existing_shared_device_profile_address_jobs(
 p_sensor text,p_campus text,p_endpoint text,p_ip inet,p_observed timestamptz
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE candidate record;
BEGIN
 IF coalesce(p_endpoint,'')='' AND p_ip IS NULL THEN RETURN; END IF;
 FOR candidate IN
  SELECT DISTINCT p.sensor_id,p.campus_id,p.endpoint_id,p.mac,p.primary_ip,p.vlan,p.address_only
  FROM shared_device_profiles p
  WHERE p.merged_into_profile_id IS NULL AND p.sensor_id=coalesce(p_sensor,'')
   AND (coalesce(p_campus,'')='' OR p.campus_id=p_campus)
   AND ((coalesce(p_endpoint,'')<>'' AND p.endpoint_id=p_endpoint) OR (p_ip IS NOT NULL AND p.primary_ip=p_ip))
 LOOP
  PERFORM enqueue_shared_device_profile_job(candidate.sensor_id,candidate.campus_id,
   CASE WHEN candidate.address_only THEN coalesce(nullif(p_endpoint,''),candidate.endpoint_id) ELSE candidate.endpoint_id END,
   candidate.mac,candidate.primary_ip,candidate.vlan,p_observed);
 END LOOP;
END $$;

CREATE OR REPLACE FUNCTION shared_device_profile_endpoint_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM enqueue_existing_shared_device_profile_identity_jobs('', '',NEW.endpoint_id,NEW.primary_mac,NEW.updated_at);
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION shared_device_profile_account_projection_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM enqueue_existing_shared_device_profile_identity_jobs(NEW.sensor_id,NEW.campus_id,
  coalesce(NEW.document->>'endpoint_id',''),coalesce(NEW.document->>'mac',''),NEW.confirmed_at);
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION shared_device_profile_session_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE row_data account_sessions; BEGIN
 row_data := CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
 PERFORM enqueue_existing_shared_device_profile_identity_jobs('', '',coalesce(row_data.endpoint_id,''),
  coalesce(row_data.mac,''),row_data.updated_at);
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;

CREATE OR REPLACE FUNCTION shared_device_profile_lease_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM enqueue_existing_shared_device_profile_address_jobs(NEW.sensor_id,NEW.campus_id,NEW.endpoint_id,NEW.ip,NEW.observed_at);
 RETURN NEW;
END $$;
