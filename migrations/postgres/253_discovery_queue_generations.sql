-- One generation per producing transaction. Different sessions can enqueue the same
-- identity or IP without blocking each other. Existing pending work is generation 0.
LOCK TABLE discovery_observation_latest IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE discovery_list_dirty ADD generation bigint NOT NULL DEFAULT 0;
ALTER TABLE discovery_list_dirty ALTER generation SET DEFAULT txid_current(),
 DROP CONSTRAINT discovery_list_dirty_pkey, ADD PRIMARY KEY(identity_key,generation);
ALTER TABLE discovery_list_ip_dirty ADD generation bigint NOT NULL DEFAULT 0;
ALTER TABLE discovery_list_ip_dirty ALTER generation SET DEFAULT txid_current(),
 DROP CONSTRAINT discovery_list_ip_dirty_pkey, ADD PRIMARY KEY(sensor_id,device_key,ip,origin,generation);

CREATE OR REPLACE FUNCTION discovery_list_dirty_key(k text) RETURNS void LANGUAGE sql AS $$
 INSERT INTO discovery_list_dirty(identity_key) VALUES(k) ON CONFLICT DO NOTHING
$$;

CREATE OR REPLACE FUNCTION discovery_list_mark_ip(f discovery_list_observation) RETURNS void LANGUAGE sql AS $$
 INSERT INTO discovery_list_ip_dirty(sensor_id,device_key,ip,origin)
 SELECT f.sensor_id,f.device_key,f.raw_ip,f.origin WHERE f.raw_ip ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
 ON CONFLICT DO NOTHING
$$;

-- Expiry is read from the summary index independently of producer generations.
CREATE FUNCTION discovery_list_compute_groups(keys text[])
RETURNS SETOF discovery_list_group_current LANGUAGE sql STABLE AS $$
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
$$;

CREATE OR REPLACE FUNCTION discovery_list_refresh_groups(batch_limit integer) RETURNS integer LANGUAGE plpgsql AS $$
DECLARE keys text[];
BEGIN
 IF batch_limit NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'invalid group batch size'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(current_schema() || ':discovery-list-groups',0)) THEN RETURN 0; END IF;
 WITH due AS MATERIALIZED (
  SELECT identity_key FROM discovery_list_group_current WHERE next_change<=now()
  ORDER BY next_change LIMIT greatest(1,batch_limit/4)
 ), picked AS MATERIALIZED (
  SELECT identity_key,generation FROM discovery_list_dirty ORDER BY enqueued_at,identity_key
  LIMIT (batch_limit-(SELECT count(*) FROM due)) FOR UPDATE SKIP LOCKED
 ), claimed AS (
  DELETE FROM discovery_list_dirty d USING picked p WHERE (d.identity_key,d.generation)=(p.identity_key,p.generation)
  RETURNING d.identity_key
 )
 SELECT ARRAY(SELECT identity_key FROM claimed UNION SELECT identity_key FROM due) INTO keys;
 IF cardinality(keys)=0 THEN RETURN 0; END IF;
 WITH computed AS MATERIALIZED (SELECT * FROM discovery_list_compute_groups(keys)), updated AS (
  INSERT INTO discovery_list_group_current AS g SELECT * FROM computed
  ON CONFLICT(identity_key,hours) DO UPDATE SET
   (computed_at,next_change,device_key,vlan,mac,last_seen,verified_until,has_ip,subnets,product_types,dhcp_types)=
   (excluded.computed_at,excluded.next_change,excluded.device_key,excluded.vlan,excluded.mac,excluded.last_seen,
    excluded.verified_until,excluded.has_ip,excluded.subnets,excluded.product_types,excluded.dhcp_types)
  WHERE (g.next_change,g.device_key,g.vlan,g.mac,g.last_seen,g.verified_until,g.has_ip,g.subnets,g.product_types,g.dhcp_types)
   IS DISTINCT FROM (excluded.next_change,excluded.device_key,excluded.vlan,excluded.mac,excluded.last_seen,
    excluded.verified_until,excluded.has_ip,excluded.subnets,excluded.product_types,excluded.dhcp_types)
 )
 DELETE FROM discovery_list_group_current g WHERE g.identity_key=ANY(keys)
 AND NOT EXISTS (SELECT 1 FROM computed c WHERE (c.identity_key,c.hours)=(g.identity_key,g.hours));
 RETURN cardinality(keys);
END $$;

CREATE OR REPLACE FUNCTION discovery_list_refresh_ips(batch_limit int) RETURNS int LANGUAGE plpgsql AS $$
DECLARE n int;
BEGIN
 IF batch_limit NOT BETWEEN 1 AND 250 THEN RAISE EXCEPTION 'invalid IPv4 batch size'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(current_schema() || ':discovery-list-ips',0)) THEN RETURN 0; END IF;
 WITH picked AS MATERIALIZED (
  SELECT * FROM discovery_list_ip_dirty ORDER BY enqueued_at,sensor_id,device_key,ip,origin LIMIT batch_limit FOR UPDATE SKIP LOCKED
 ), claimed AS (
  DELETE FROM discovery_list_ip_dirty d USING picked p
  WHERE (d.sensor_id,d.device_key,d.ip,d.origin,d.generation)=(p.sensor_id,p.device_key,p.ip,p.origin,p.generation)
  RETURNING d.sensor_id,d.device_key,d.ip,d.origin
 ), edges AS (SELECT DISTINCT * FROM claimed), latest AS MATERIALIZED (
  SELECT p.*, (SELECT observed_at FROM discovery_list_observation f
   WHERE (f.sensor_id,f.device_key,f.raw_ip,f.origin)=(p.sensor_id,p.device_key,p.ip,p.origin) ORDER BY observed_at DESC LIMIT 1) last_seen
  FROM edges p
 ), changed AS (
  INSERT INTO discovery_list_ip_current SELECT sensor_id,device_key,ip,origin,last_seen FROM latest WHERE last_seen IS NOT NULL
   ON CONFLICT(sensor_id,device_key,ip,origin) DO UPDATE SET last_seen=excluded.last_seen
   WHERE discovery_list_ip_current.last_seen<>excluded.last_seen
 ), removed AS (
  DELETE FROM discovery_list_ip_current c USING latest l WHERE (c.sensor_id,c.device_key,c.ip,c.origin)=(l.sensor_id,l.device_key,l.ip,l.origin) AND l.last_seen IS NULL
 )
 SELECT count(*) INTO n FROM claimed;
 RETURN n;
END $$;
