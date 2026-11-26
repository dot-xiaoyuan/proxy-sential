-- 补齐 discovery_list_compute_groups 中的 capwap、dahua_discovery 与 ssh_banner 被动发现协议来源。
CREATE OR REPLACE FUNCTION discovery_list_compute_groups(keys text[])
RETURNS SETOF discovery_list_group_current LANGUAGE sql STABLE AS $$
 WITH members AS MATERIALIZED (
   SELECT k,f.*,count(*) OVER(PARTITION BY k) group_size
   FROM unnest(keys) k CROSS JOIN LATERAL (
    SELECT origin,device_key,observed_at,valid_until,vlan,raw_mac,raw_ip,scope_valid AND sensor_id<>'' AND site_id<>'' AND access_domain<>'' verified,product_status,product_type,dhcp_type
    FROM discovery_list_observation WHERE base_identity=k AND observed_at>=now()-interval '30 days'
     AND origin IN ('dhcp','arp','ndp','dns_sd','ssdp','ws_discovery','sadp','capwap','dahua_discovery','ieee1905','ieee1905_client','lldp','cdp','snmp','bacnet','modbus','http_device','rtsp','sip','tls_device','ipp','onvif','dhcp_client','ssh_banner')
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
