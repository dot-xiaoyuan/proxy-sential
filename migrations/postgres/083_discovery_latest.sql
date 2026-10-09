CREATE TABLE IF NOT EXISTS discovery_observation_latest (
 device_key text NOT NULL,source_id text NOT NULL,origin text NOT NULL,service_type text NOT NULL,port text NOT NULL,
 id text NOT NULL,observed_at timestamptz NOT NULL,valid_until timestamptz NOT NULL,withdrawn boolean NOT NULL,data jsonb NOT NULL,
 PRIMARY KEY(device_key,source_id,origin,service_type,port)
);
CREATE INDEX IF NOT EXISTS discovery_latest_active ON discovery_observation_latest(valid_until,device_key,observed_at DESC) WHERE NOT withdrawn;
CREATE INDEX IF NOT EXISTS discovery_latest_observed ON discovery_observation_latest(observed_at);
CREATE OR REPLACE FUNCTION project_discovery_observation_latest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO discovery_observation_latest VALUES(NEW.device_key,NEW.source_id,NEW.origin,coalesce(NEW.data->'evidence'->'payload'->>'service_type',''),coalesce(NEW.data->>'port',''),NEW.id,NEW.observed_at,NEW.valid_until,NEW.withdrawn,NEW.data)
 ON CONFLICT(device_key,source_id,origin,service_type,port) DO UPDATE SET id=EXCLUDED.id,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,data=EXCLUDED.data
 WHERE (EXCLUDED.observed_at,EXCLUDED.id)>=(discovery_observation_latest.observed_at,discovery_observation_latest.id);
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS discovery_observation_latest_dirty ON discovery_observations;
CREATE TRIGGER discovery_observation_latest_dirty AFTER INSERT OR UPDATE ON discovery_observations FOR EACH ROW EXECUTE FUNCTION project_discovery_observation_latest();
INSERT INTO discovery_observation_latest
SELECT DISTINCT ON(device_key,source_id,origin,coalesce(data->'evidence'->'payload'->>'service_type',''),coalesce(data->>'port','')) device_key,source_id,origin,coalesce(data->'evidence'->'payload'->>'service_type',''),coalesce(data->>'port',''),id,observed_at,valid_until,withdrawn,data FROM discovery_observations
ORDER BY device_key,source_id,origin,coalesce(data->'evidence'->'payload'->>'service_type',''),coalesce(data->>'port',''),observed_at DESC,id DESC
ON CONFLICT(device_key,source_id,origin,service_type,port) DO UPDATE SET id=EXCLUDED.id,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,data=EXCLUDED.data
WHERE (EXCLUDED.observed_at,EXCLUDED.id)>=(discovery_observation_latest.observed_at,discovery_observation_latest.id);
