-- Keep distinct verified SNMP response field sets in the maintained latest index.
-- No history rewrite or backfill. Old writers retain the existing empty partition.
-- Values do not enter the partition hash; repeats update one row per scoped source.
CREATE OR REPLACE FUNCTION project_discovery_observation_latest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO discovery_observation_latest VALUES(NEW.device_key,NEW.source_id,NEW.origin,coalesce(nullif(NEW.data->>'latest_partition',''),NEW.data->'evidence'->'payload'->>'service_type',''),coalesce(NEW.data->>'port',''),NEW.id,NEW.observed_at,NEW.valid_until,NEW.withdrawn,NEW.data)
 ON CONFLICT(device_key,source_id,origin,service_type,port) DO UPDATE SET id=EXCLUDED.id,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,data=EXCLUDED.data
 WHERE (EXCLUDED.observed_at,EXCLUDED.id)>=(discovery_observation_latest.observed_at,discovery_observation_latest.id);
 RETURN NEW;
END $$;
