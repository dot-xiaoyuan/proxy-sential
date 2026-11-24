-- Narrow, replaceable projection of the latest discovery facts. No evidence
-- documents or history are copied. Enable the writer triggers only on the
-- passive installation, before starting the resumable adoption.
CREATE TABLE discovery_list_observation (
 device_key text NOT NULL, source_id text NOT NULL, origin text NOT NULL, service_type text NOT NULL, port text NOT NULL,
 id text NOT NULL, observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL,
 sensor_id text NOT NULL, site_id text NOT NULL, access_domain text NOT NULL, vlan text NOT NULL, vrf text NOT NULL,
 raw_ip text NOT NULL, raw_mac text NOT NULL, name text NOT NULL, device_type text NOT NULL, manufacturer text NOT NULL, model text NOT NULL,
 scope_valid boolean NOT NULL, source_campus text NOT NULL, capabilities jsonb NOT NULL, strong_service boolean NOT NULL,
 product_status text NOT NULL, product_type text NOT NULL, dhcp_type text NOT NULL,
 base_identity text COLLATE "C" NOT NULL,
 PRIMARY KEY(device_key,source_id,origin,service_type,port)
);
CREATE INDEX discovery_list_observation_event ON discovery_list_observation(id);
CREATE INDEX discovery_list_observation_seen ON discovery_list_observation(observed_at DESC,base_identity);
CREATE INDEX discovery_list_observation_member ON discovery_list_observation(base_identity,observed_at DESC);
CREATE INDEX discovery_list_observation_ip ON discovery_list_observation(sensor_id,raw_ip,observed_at DESC);

CREATE FUNCTION discovery_list_project(l discovery_observation_latest)
RETURNS discovery_list_observation LANGUAGE sql IMMUTABLE AS $$
 SELECT l.device_key,l.source_id,l.origin,l.service_type,l.port,l.id,l.observed_at,l.valid_until,
 coalesce(d.node,''),coalesce(d.site,''),coalesce(d.domain,''),coalesce(d.vlan,''),coalesce(d.vrf,''),
 coalesce(d.ip,''),coalesce(d.mac,''),coalesce(d.name,''),coalesce(d.device_type,''),coalesce(d.manufacturer,''),coalesce(d.model_name,''),
 coalesce(d.evidence->'observer'->>'capture_scope_issue','')='',coalesce(d.evidence->'subject'->>'campus_id',''),
 CASE WHEN l.origin IN ('lldp','cdp') AND lower(concat_ws(' ',d.name,d.evidence->'payload'->>'system_name',d.evidence->'payload'->>'system_description')) LIKE '%ikuai%'
 THEN coalesce(d.capabilities,'[]'::jsonb)||'["routing"]'::jsonb ELSE coalesce(d.capabilities,'[]'::jsonb) END,
 coalesce(d.confidence IN ('strong','confirmed'),false),
 CASE WHEN d.product_clue->>'attribution' IN ('response_ip','request_ip') AND d.product_clue->>'event_id'=d.event_id
 AND d.product_clue->>'ip'=d.ip AND d.product_clue->>'sensor_id'=d.node AND d.product_clue->>'site'=d.site
 AND d.product_clue->>'domain'=d.domain AND coalesce(d.product_clue->>'vlan','')=coalesce(d.vlan,'')
 AND coalesce(d.product_clue->>'vrf','')=coalesce(d.vrf,'') THEN coalesce(d.product_clue->>'product_status','') ELSE '' END,
 coalesce(d.product_clue->>'type',''), coalesce(d.evidence->'payload'->>'dhcp_candidate_type',''),
 CASE WHEN coalesce(d.mac,'')<>'' THEN jsonb_build_array('identity',coalesce(d.node,''),coalesce(d.site,''),coalesce(d.domain,''),coalesce(d.vlan,''),coalesce(d.vrf,''),'mac',lower(d.mac))::text
 ELSE jsonb_build_array('discovery_key',l.device_key)::text END
 FROM jsonb_to_record(CASE WHEN jsonb_typeof(l.data)='object' THEN l.data END)
 AS d(node text,site text,domain text,vlan text,vrf text,ip text,mac text,name text,device_type text,manufacturer text,model_name text,
      evidence jsonb,capabilities jsonb,confidence text,event_id text,product_clue jsonb)
$$;

CREATE FUNCTION discovery_list_put(l discovery_observation_latest) RETURNS void LANGUAGE sql AS $$
 INSERT INTO discovery_list_observation AS o SELECT * FROM discovery_list_project(l)
 ON CONFLICT(device_key,source_id,origin,service_type,port) DO UPDATE SET
 (id,observed_at,valid_until,sensor_id,site_id,access_domain,vlan,vrf,raw_ip,raw_mac,name,device_type,manufacturer,model,scope_valid,source_campus,capabilities,strong_service,product_status,product_type,dhcp_type,base_identity)=
 (excluded.id,excluded.observed_at,excluded.valid_until,excluded.sensor_id,excluded.site_id,excluded.access_domain,excluded.vlan,excluded.vrf,excluded.raw_ip,excluded.raw_mac,excluded.name,excluded.device_type,excluded.manufacturer,excluded.model,excluded.scope_valid,excluded.source_campus,excluded.capabilities,excluded.strong_service,excluded.product_status,excluded.product_type,excluded.dhcp_type,excluded.base_identity)
 WHERE o IS DISTINCT FROM excluded
$$;

CREATE FUNCTION discovery_list_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND (OLD.device_key,OLD.source_id,OLD.origin,OLD.service_type,OLD.port)
      IS DISTINCT FROM (NEW.device_key,NEW.source_id,NEW.origin,NEW.service_type,NEW.port)) THEN
   DELETE FROM discovery_list_observation WHERE (device_key,source_id,origin,service_type,port)=(OLD.device_key,OLD.source_id,OLD.origin,OLD.service_type,OLD.port);
 END IF;
 IF TG_OP<>'DELETE' THEN
   IF NEW.withdrawn THEN
     DELETE FROM discovery_list_observation WHERE (device_key,source_id,origin,service_type,port)=(NEW.device_key,NEW.source_id,NEW.origin,NEW.service_type,NEW.port);
   ELSE
     PERFORM discovery_list_put(NEW);
   END IF;
 END IF;
 RETURN NULL;
END $$;

CREATE TRIGGER discovery_list_sync AFTER INSERT OR UPDATE OR DELETE ON discovery_observation_latest FOR EACH ROW EXECUTE FUNCTION discovery_list_sync();
ALTER TABLE discovery_observation_latest DISABLE TRIGGER discovery_list_sync;
CREATE FUNCTION discovery_list_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN TRUNCATE discovery_list_observation; RETURN NULL; END $$;
CREATE TRIGGER discovery_list_truncate AFTER TRUNCATE ON discovery_observation_latest EXECUTE FUNCTION discovery_list_truncate();
ALTER TABLE discovery_observation_latest DISABLE TRIGGER discovery_list_truncate;

CREATE TABLE discovery_list_adoption (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 last_key text[], complete boolean NOT NULL DEFAULT false
);
INSERT INTO discovery_list_adoption DEFAULT VALUES;

-- Lock the source row before projecting it so a concurrent correction cannot
-- be overwritten by an older adoption snapshot. The cursor and rows commit together.
CREATE FUNCTION discovery_list_adopt(batch_limit int) RETURNS boolean LANGUAGE plpgsql SET plan_cache_mode=force_custom_plan AS $$
DECLARE cursor_key text[]; finished boolean; n int := 0; row_bytes bigint := 0; fact discovery_observation_latest;
BEGIN
 IF batch_limit NOT BETWEEN 1 AND 250 THEN RAISE EXCEPTION 'invalid adoption batch size'; END IF;
 SELECT last_key,complete INTO STRICT cursor_key,finished FROM discovery_list_adoption WHERE singleton FOR UPDATE;
 IF finished THEN RETURN true; END IF;
 IF (SELECT count(*) FROM pg_trigger WHERE tgrelid='discovery_observation_latest'::regclass AND tgname IN ('discovery_list_sync','discovery_list_truncate') AND tgenabled IN ('O','A'))<>2 THEN
   RAISE EXCEPTION 'enable discovery list writers before adoption';
 END IF;
 FOR fact IN SELECT l.* FROM discovery_observation_latest l
    WHERE (cursor_key IS NULL OR (l.device_key,l.source_id,l.origin,l.service_type,l.port)>(cursor_key[1],cursor_key[2],cursor_key[3],cursor_key[4],cursor_key[5]))
    ORDER BY l.device_key,l.source_id,l.origin,l.service_type,l.port LIMIT batch_limit FOR UPDATE OF l
 LOOP
   IF NOT fact.withdrawn THEN PERFORM discovery_list_put(fact); END IF;
   cursor_key:=ARRAY[fact.device_key,fact.source_id,fact.origin,fact.service_type,fact.port];
   n:=n+1; row_bytes:=row_bytes+pg_column_size(fact.data);
   IF row_bytes>=1048576 THEN EXIT; END IF;
 END LOOP;
 UPDATE discovery_list_adoption SET last_key=cursor_key,complete=(n=0) WHERE singleton;
 RETURN n=0;
END $$;

-- Only ordinary scoped MAC identities enter this acceleration. IP-only,
-- disputed, oversized or recently changed groups use the structured facts.
CREATE TABLE discovery_list_dirty (
 identity_key text COLLATE "C" PRIMARY KEY, enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX discovery_list_dirty_oldest ON discovery_list_dirty(enqueued_at,identity_key);
CREATE TABLE discovery_list_group_current (
 identity_key text COLLATE "C" NOT NULL, hours integer NOT NULL,
 computed_at timestamptz NOT NULL, next_change timestamptz NOT NULL,
 device_key text NOT NULL, vlan text NOT NULL, mac text NOT NULL, last_seen timestamptz NOT NULL,
 verified_until timestamptz, has_ip boolean NOT NULL, subnets text[] NOT NULL,
 product_types text[] NOT NULL, dhcp_types text[] NOT NULL,
 PRIMARY KEY(identity_key,hours)
);
CREATE INDEX discovery_list_group_page ON discovery_list_group_current(hours,last_seen DESC,identity_key);
CREATE INDEX discovery_list_group_expiry ON discovery_list_group_current(next_change,identity_key);
CREATE INDEX discovery_list_empty_mac ON discovery_list_observation(id) WHERE raw_mac='';

CREATE FUNCTION discovery_list_dirty_key(k text) RETURNS void LANGUAGE sql AS $$
 INSERT INTO discovery_list_dirty(identity_key) VALUES(k)
 ON CONFLICT(identity_key) DO UPDATE SET enqueued_at=discovery_list_dirty.enqueued_at
$$;

CREATE FUNCTION discovery_list_mark_group() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' AND OLD.raw_mac ~* '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$' THEN
   PERFORM discovery_list_dirty_key(OLD.base_identity);
 END IF;
 IF TG_OP<>'DELETE' AND (TG_OP='INSERT' OR NEW.base_identity<>OLD.base_identity)
    AND NEW.raw_mac ~* '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$' THEN
   PERFORM discovery_list_dirty_key(NEW.base_identity);
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER discovery_list_mark_group AFTER INSERT OR UPDATE OR DELETE ON discovery_list_observation FOR EACH ROW EXECUTE FUNCTION discovery_list_mark_group();

-- Claiming and acknowledging share a transaction. A concurrent writer either
-- precedes the claim or queues another pass after its row lock is released.
CREATE FUNCTION discovery_list_refresh_groups(batch_limit integer) RETURNS integer LANGUAGE plpgsql AS $$
DECLARE keys text[];
BEGIN
 IF batch_limit NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'invalid group batch size'; END IF;
 INSERT INTO discovery_list_dirty(identity_key)
 SELECT identity_key FROM (SELECT identity_key FROM discovery_list_group_current WHERE next_change<=now() ORDER BY next_change LIMIT batch_limit) due
 GROUP BY identity_key ORDER BY identity_key ON CONFLICT DO NOTHING;
 SELECT array_agg(identity_key ORDER BY identity_key) INTO keys FROM (
   SELECT identity_key FROM discovery_list_dirty ORDER BY enqueued_at,identity_key LIMIT batch_limit FOR UPDATE SKIP LOCKED
 ) claimed;
 IF keys IS NULL THEN RETURN 0; END IF;
 DELETE FROM discovery_list_group_current WHERE identity_key=ANY(keys);
 INSERT INTO discovery_list_group_current(identity_key,hours,computed_at,next_change,device_key,vlan,mac,last_seen,verified_until,has_ip,subnets,product_types,dhcp_types)
 WITH members AS MATERIALIZED (
   SELECT k,f.*,count(*) OVER(PARTITION BY k) group_size
   FROM unnest(keys) k CROSS JOIN LATERAL (
    SELECT origin,device_key,observed_at,valid_until,vlan,raw_mac,raw_ip,scope_valid AND sensor_id<>'' AND site_id<>'' AND access_domain<>'' verified,product_status,product_type,dhcp_type
    FROM discovery_list_observation WHERE base_identity=k AND observed_at>=now()-interval '30 days'
     AND origin IN ('dhcp','arp','ndp','dns_sd','ssdp','ws_discovery','sadp','ieee1905_client','lldp','cdp','snmp','bacnet','modbus','http_device','rtsp','sip','tls_device','ipp','onvif','dhcp_client')
    ORDER BY observed_at DESC LIMIT 65
   ) f
 ), windows AS (SELECT h,make_interval(hours=>h) span FROM unnest(ARRAY[24,168,720]) h),
 eligible AS (
  SELECT m.*,w.*,CASE WHEN verified AND valid_until>now() AND origin IN ('dhcp','arp','ndp') AND pg_input_is_valid(raw_ip,'inet') THEN
    network(set_masklen(raw_ip::inet,CASE family(raw_ip::inet) WHEN 4 THEN 24 ELSE 64 END))::text END subnet
  FROM members m CROSS JOIN windows w
  WHERE group_size<=64 AND raw_mac<>'00:00:00:00:00:00' AND observed_at>=now()-span
 )
 SELECT k,h,now(),least(min(observed_at+span),min(valid_until) FILTER(WHERE valid_until>now()),min(observed_at) FILTER(WHERE observed_at>now())),
   min(device_key COLLATE "C") FILTER(WHERE observed_at<=now()),max(vlan),min(lower(raw_mac)),
   max(observed_at) FILTER(WHERE observed_at<=now()),max(valid_until) FILTER(WHERE verified AND observed_at<=now()),
   bool_or(raw_ip<>'') FILTER(WHERE observed_at<=now()),
   coalesce(array_agg(DISTINCT subnet ORDER BY subnet) FILTER(WHERE subnet IS NOT NULL AND observed_at<=now()),'{}'),
   coalesce(array_agg(DISTINCT product_type ORDER BY product_type) FILTER(WHERE valid_until>now() AND product_status='identified' AND product_type<>'' AND observed_at<=now()),'{}'),
   coalesce(array_agg(DISTINCT dhcp_type ORDER BY dhcp_type) FILTER(WHERE valid_until>now() AND verified AND origin IN ('dhcp_client','dhcp') AND dhcp_type<>'' AND observed_at<=now()),'{}')
 FROM eligible GROUP BY k,h HAVING bool_or(observed_at<=now());
 DELETE FROM discovery_list_dirty WHERE identity_key=ANY(keys);
 RETURN cardinality(keys);
END $$;
CREATE FUNCTION discovery_list_groups_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN TRUNCATE discovery_list_dirty,discovery_list_group_current; RETURN NULL; END $$;
CREATE TRIGGER discovery_list_groups_truncate AFTER TRUNCATE ON discovery_list_observation EXECUTE FUNCTION discovery_list_groups_truncate();

-- The coverage unit is an IPv4 address. Store one contribution per address,
-- device key and protocol; one address can belong to several scoped identities.
CREATE TABLE discovery_list_ip_current (
 sensor_id text NOT NULL,device_key text NOT NULL,ip text NOT NULL,origin text NOT NULL,last_seen timestamptz NOT NULL,
 PRIMARY KEY(sensor_id,device_key,ip,origin)
);
CREATE INDEX discovery_list_ip_seen ON discovery_list_ip_current(sensor_id,last_seen);
CREATE TABLE discovery_list_ip_dirty (
 sensor_id text NOT NULL,device_key text NOT NULL,ip text NOT NULL,origin text NOT NULL,enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(sensor_id,device_key,ip,origin)
);
CREATE INDEX discovery_list_ip_oldest ON discovery_list_ip_dirty(enqueued_at,sensor_id,device_key,ip,origin);
CREATE INDEX discovery_list_ip_member ON discovery_list_observation(sensor_id,device_key,raw_ip,origin,observed_at DESC);
CREATE FUNCTION discovery_list_mark_ip(f discovery_list_observation) RETURNS void LANGUAGE sql AS $$
 INSERT INTO discovery_list_ip_dirty(sensor_id,device_key,ip,origin)
 SELECT f.sensor_id,f.device_key,f.raw_ip,f.origin WHERE f.raw_ip ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
 ON CONFLICT(sensor_id,device_key,ip,origin) DO UPDATE SET enqueued_at=discovery_list_ip_dirty.enqueued_at
$$;
CREATE FUNCTION discovery_list_sync_ip() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' AND (TG_OP='DELETE' OR (OLD.sensor_id,OLD.device_key,OLD.raw_ip,OLD.origin) IS DISTINCT FROM (NEW.sensor_id,NEW.device_key,NEW.raw_ip,NEW.origin)) THEN
   PERFORM discovery_list_mark_ip(OLD);
 END IF;
 IF TG_OP<>'DELETE' AND (TG_OP='INSERT' OR (NEW.sensor_id,NEW.device_key,NEW.raw_ip,NEW.origin,NEW.observed_at) IS DISTINCT FROM (OLD.sensor_id,OLD.device_key,OLD.raw_ip,OLD.origin,OLD.observed_at)) THEN
   PERFORM discovery_list_mark_ip(NEW);
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER discovery_list_sync_ip AFTER INSERT OR UPDATE OR DELETE ON discovery_list_observation FOR EACH ROW EXECUTE FUNCTION discovery_list_sync_ip();

CREATE FUNCTION discovery_list_refresh_ips(batch_limit int) RETURNS int LANGUAGE plpgsql AS $$
DECLARE n int;
BEGIN
 IF batch_limit NOT BETWEEN 1 AND 250 THEN RAISE EXCEPTION 'invalid IPv4 batch size'; END IF;
 WITH picked AS MATERIALIZED (
  SELECT * FROM discovery_list_ip_dirty ORDER BY enqueued_at,sensor_id,device_key,ip,origin LIMIT batch_limit FOR UPDATE SKIP LOCKED
 ), latest AS MATERIALIZED (
  SELECT p.*, (SELECT observed_at FROM discovery_list_observation f
   WHERE (f.sensor_id,f.device_key,f.raw_ip,f.origin)=(p.sensor_id,p.device_key,p.ip,p.origin) ORDER BY observed_at DESC LIMIT 1) last_seen
  FROM picked p
 ), changed AS (
  INSERT INTO discovery_list_ip_current SELECT sensor_id,device_key,ip,origin,last_seen FROM latest WHERE last_seen IS NOT NULL
   ON CONFLICT(sensor_id,device_key,ip,origin) DO UPDATE SET last_seen=excluded.last_seen
   WHERE discovery_list_ip_current.last_seen<>excluded.last_seen
 ), removed AS (
  DELETE FROM discovery_list_ip_current c USING latest l WHERE (c.sensor_id,c.device_key,c.ip,c.origin)=(l.sensor_id,l.device_key,l.ip,l.origin) AND l.last_seen IS NULL
 )
 DELETE FROM discovery_list_ip_dirty d USING picked p WHERE (d.sensor_id,d.device_key,d.ip,d.origin)=(p.sensor_id,p.device_key,p.ip,p.origin);
 GET DIAGNOSTICS n=ROW_COUNT;
 RETURN n;
END $$;
CREATE OR REPLACE FUNCTION discovery_list_groups_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN TRUNCATE discovery_list_dirty,discovery_list_group_current,discovery_list_ip_dirty,discovery_list_ip_current; RETURN NULL; END $$;

CREATE FUNCTION discovery_list_assert_ready() RETURNS boolean LANGUAGE plpgsql STABLE AS $$
BEGIN
 IF NOT coalesce((SELECT complete FROM discovery_list_adoption WHERE singleton),false)
   OR (SELECT count(*) FROM pg_trigger WHERE tgrelid='discovery_observation_latest'::regclass AND tgname IN ('discovery_list_sync','discovery_list_truncate') AND tgenabled IN ('O','A'))<>2 THEN
  RAISE EXCEPTION 'discovery list projection is not ready';
 END IF;
 RETURN true;
END $$;
