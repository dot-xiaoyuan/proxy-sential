-- Rows exist only for retained address-only observations with a current link.
-- Producers only enqueue an ID. Per-transaction generations preserve races
-- between a newly observed address and a link committed by another writer.
CREATE TABLE discovery_address_link_current (
 observation_id text PRIMARY KEY, endpoint_id text NOT NULL
);
CREATE TABLE discovery_address_link_dirty (
 observation_id text NOT NULL, generation bigint NOT NULL DEFAULT txid_current(),
 queued_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(observation_id,generation)
);
CREATE INDEX discovery_address_link_oldest ON discovery_address_link_dirty(queued_at,observation_id);
CREATE TABLE discovery_address_link_adoption (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), last_id text, complete boolean NOT NULL DEFAULT false
);
INSERT INTO discovery_address_link_adoption DEFAULT VALUES;

CREATE FUNCTION discovery_address_link_queue(k text) RETURNS void LANGUAGE sql AS $$
 INSERT INTO discovery_address_link_dirty(observation_id) VALUES(k) ON CONFLICT DO NOTHING
$$;
CREATE FUNCTION discovery_address_fact_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (OLD.id,OLD.raw_mac) IS NOT DISTINCT FROM (NEW.id,NEW.raw_mac) THEN RETURN NULL; END IF;
 IF TG_OP<>'INSERT' AND OLD.raw_mac='' THEN PERFORM discovery_address_link_queue(OLD.id); END IF;
 IF TG_OP<>'DELETE' AND NEW.raw_mac='' THEN PERFORM discovery_address_link_queue(NEW.id); END IF;
 RETURN NULL;
END $$;
CREATE FUNCTION discovery_address_identity_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (OLD.observation_id,OLD.endpoint_id) IS NOT DISTINCT FROM (NEW.observation_id,NEW.endpoint_id) THEN RETURN NULL; END IF;
 IF TG_OP<>'INSERT' THEN PERFORM discovery_address_link_queue(OLD.observation_id); END IF;
 IF TG_OP<>'DELETE' THEN PERFORM discovery_address_link_queue(NEW.observation_id); END IF;
 RETURN NULL;
END $$;
CREATE FUNCTION discovery_address_links_truncated() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN TRUNCATE discovery_address_link_dirty, discovery_address_link_current; RETURN NULL; END $$;
CREATE TRIGGER discovery_address_fact AFTER INSERT OR UPDATE OF id,raw_mac OR DELETE ON discovery_list_observation FOR EACH ROW EXECUTE FUNCTION discovery_address_fact_changed();
CREATE TRIGGER discovery_address_identity AFTER INSERT OR UPDATE OF observation_id,endpoint_id OR DELETE ON discovery_identity_links FOR EACH ROW EXECUTE FUNCTION discovery_address_identity_changed();
CREATE TRIGGER discovery_address_fact_clear AFTER TRUNCATE ON discovery_list_observation EXECUTE FUNCTION discovery_address_links_truncated();
CREATE TRIGGER discovery_address_identity_clear AFTER TRUNCATE ON discovery_identity_links EXECUTE FUNCTION discovery_address_links_truncated();
ALTER TABLE discovery_list_observation DISABLE TRIGGER discovery_address_fact;
ALTER TABLE discovery_list_observation DISABLE TRIGGER discovery_address_fact_clear;
ALTER TABLE discovery_identity_links DISABLE TRIGGER discovery_address_identity;
ALTER TABLE discovery_identity_links DISABLE TRIGGER discovery_address_identity_clear;

CREATE FUNCTION discovery_address_links_ready() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT complete AND (SELECT count(*)=4 FROM pg_trigger WHERE
 (tgrelid,tgname) IN (('discovery_list_observation'::regclass,'discovery_address_fact'),('discovery_list_observation'::regclass,'discovery_address_fact_clear'),
 ('discovery_identity_links'::regclass,'discovery_address_identity'),('discovery_identity_links'::regclass,'discovery_address_identity_clear'))
 AND tgenabled IN ('O','A')) FROM discovery_address_link_adoption WHERE singleton
$$;
CREATE FUNCTION discovery_address_links_refresh(batch_limit int) RETURNS integer LANGUAGE plpgsql SET plan_cache_mode=force_custom_plan AS $$
DECLARE cursor_id text; adopted boolean; ids text[]; n int;
BEGIN
 IF batch_limit NOT BETWEEN 1 AND 250 THEN RAISE EXCEPTION 'invalid address link batch size'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(current_schema()||':discovery-address-links',0)) THEN RETURN 0; END IF;
 SELECT last_id,complete INTO STRICT cursor_id,adopted FROM discovery_address_link_adoption WHERE singleton;
 IF NOT adopted THEN
  IF (SELECT count(*) FROM pg_trigger WHERE tgrelid IN ('discovery_list_observation'::regclass,'discovery_identity_links'::regclass)
   AND tgname IN ('discovery_address_fact','discovery_address_fact_clear','discovery_address_identity','discovery_address_identity_clear') AND tgenabled IN ('O','A'))<>4
   THEN RAISE EXCEPTION 'address link writers disabled'; END IF;
  SELECT ARRAY(SELECT DISTINCT id FROM discovery_list_observation WHERE raw_mac='' AND (cursor_id IS NULL OR id>cursor_id) ORDER BY id LIMIT batch_limit) INTO ids;
  INSERT INTO discovery_address_link_dirty(observation_id) SELECT unnest(ids) ON CONFLICT DO NOTHING;
  UPDATE discovery_address_link_adoption SET last_id=coalesce(ids[cardinality(ids)],last_id),complete=(cardinality(ids)<batch_limit) WHERE singleton;
 END IF;
 WITH picked AS MATERIALIZED (
  SELECT observation_id,generation FROM discovery_address_link_dirty ORDER BY queued_at,observation_id LIMIT batch_limit FOR UPDATE SKIP LOCKED
 ), claimed AS (
  DELETE FROM discovery_address_link_dirty d USING picked p WHERE (d.observation_id,d.generation)=(p.observation_id,p.generation) RETURNING d.observation_id
 ), resolved AS MATERIALIZED (
  SELECT DISTINCT c.observation_id,i.endpoint_id FROM claimed c LEFT JOIN discovery_identity_links i
  ON i.observation_id=c.observation_id AND EXISTS(SELECT 1 FROM discovery_list_observation f WHERE f.raw_mac='' AND f.id=c.observation_id)
 ), changed AS (
  INSERT INTO discovery_address_link_current SELECT * FROM resolved WHERE endpoint_id IS NOT NULL
  ON CONFLICT(observation_id) DO UPDATE SET endpoint_id=excluded.endpoint_id WHERE discovery_address_link_current.endpoint_id<>excluded.endpoint_id
 ), removed AS (
  DELETE FROM discovery_address_link_current l USING resolved r WHERE l.observation_id=r.observation_id AND r.endpoint_id IS NULL
 )
 SELECT count(*) INTO n FROM claimed;
 RETURN n;
END $$;

-- At most six latest successful documents per sensor. Readers never wait for
-- publication and a failed publication leaves the last successful version intact.
CREATE TABLE discovery_report_publications (
 sensor_id text NOT NULL, report text NOT NULL CHECK(report IN ('metadata','coverage')),
 hours integer NOT NULL CHECK(hours IN (24,168,720)), bucket_start timestamptz NOT NULL,
 as_of timestamptz NOT NULL, published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 document jsonb NOT NULL, PRIMARY KEY(sensor_id,report,hours)
);
