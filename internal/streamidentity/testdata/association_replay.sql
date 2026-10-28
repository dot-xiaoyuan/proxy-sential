-- All input is a CTE: this replay never reads or writes application tables.
-- The marker is replaced with the exact production lateral SQL by the test.
WITH cases(id,signal_patch,binding_patches,copies,expected) AS (VALUES
 ('dhcp_client', '{"protocol":"dhcp","mac":"02:00:00:00:00:01"}'::jsonb, '[]'::jsonb,1,'02:00:00:00:00:01'),
 ('dhcpv6_client', '{"protocol":"dhcpv6","mac":"02:00:00:00:00:01"}', '[]',1,'02:00:00:00:00:01'),
 ('link_device', '{"protocol":"lldp","ip":"","mac":"02:00:00:00:00:01"}', '[]',1,'02:00:00:00:00:01'),
 ('no_binding', '{}', '[]',1,NULL),
 ('unique_binding', '{}', '[{}]',1,'02:00:00:00:00:01'),
 ('matching_mac', '{"mac":"02:00:00:00:00:01"}', '[{}]',1,'02:00:00:00:00:01'),
 ('gateway_mac', '{"mac":"02:00:00:00:00:ff"}', '[{}]',1,NULL),
 ('duplicate_sources', '{}', '[{},{}]',1,'02:00:00:00:00:01'),
 ('competing_macs', '{}', '[{},{"mac":"02:00:00:00:00:02"}]',1,NULL),
 ('other_ip', '{}', '[{"ip":"192.0.2.2"}]',1,NULL),
 ('other_sensor', '{}', '[{"sensor_id":"other"}]',1,NULL),
 ('other_site', '{}', '[{"site":"other"}]',1,NULL),
 ('other_domain', '{}', '[{"domain":"other"}]',1,NULL),
 ('other_vlan', '{}', '[{"vlan":"993"}]',1,NULL),
 ('other_vrf', '{}', '[{"vrf":"other"}]',1,NULL),
 ('other_interface', '{}', '[{"interface_name":"bond1"}]',1,NULL),
 ('missing_scope', '{"domain":null}', '[{}]',1,NULL),
 ('untagged_is_not_wildcard', '{"vlan":""}', '[{}]',1,NULL),
 ('withdrawn', '{}', '[{"withdrawn":true}]',1,NULL),
 ('not_a_binding', '{}', '[{"address_binding":false}]',1,NULL),
 ('not_a_binding_protocol', '{}', '[{"protocol":"ssdp"}]',1,NULL),
 ('empty_binding_mac', '{}', '[{"mac":""}]',1,NULL),
 ('closed_epoch', '{}', '[{"epoch":"closed"}]',1,NULL),
 ('expired_now', '{}', '[{"valid_until":"2000-01-01T00:00:00Z"}]',1,NULL),
 ('future_binding', '{}', '[{"observed_at":"2100-01-01T00:00:00Z"}]',1,NULL),
 ('renewal_after_signal', '{}', '[{"observed_offset_seconds":-30}]',1,NULL),
 ('old_signal', '{"observed_offset_seconds":-300}', '[{}]',1,NULL),
 ('arp_binding', '{}', '[{"protocol":"arp"}]',1,'02:00:00:00:00:01'),
 ('ndp_binding', '{}', '[{"protocol":"ndp"}]',1,'02:00:00:00:00:01'),
 ('dhcpv6_binding', '{}', '[{"protocol":"dhcpv6"}]',1,'02:00:00:00:00:01'),
 ('withdrawn_competitor', '{}', '[{},{"mac":"02:00:00:00:00:02","withdrawn":true}]',1,'02:00:00:00:00:01'),
 ('saturation', '{}', '[{}]',65,NULL),
 ('below_budget', '{}', '[{}]',64,'02:00:00:00:00:01')
), defaults AS (
 SELECT jsonb_build_object('protocol','dns_sd','mac','','ip','192.0.2.1',
  'sensor','sensor','site','site','domain','access','vlan','992','vrf','','interface','bond0',
  'observed',now()-interval '1 minute') AS signal,
 jsonb_build_object('epoch','live','protocol','dhcp','mac','02:00:00:00:00:01','ip','192.0.2.1',
  'sensor_id','sensor','site','site','domain','access','vlan','992','vrf','','interface_name','bond0',
  'address_binding',true,'withdrawn',false,'observed_at',now()-interval '2 minutes',
  'valid_until',now()+interval '30 minutes') AS binding
), resolved AS (
 SELECT scenario.id,scenario.expected,actual.mac FROM cases scenario CROSS JOIN defaults d
 LEFT JOIN LATERAL (
  WITH stream_source_cutovers(epoch,state) AS (VALUES ('live','active'),('closed','closed')),
  stream_discovery_facts AS (
   SELECT f.* FROM jsonb_array_elements(scenario.binding_patches) p
   CROSS JOIN generate_series(1,scenario.copies)
   CROSS JOIN LATERAL jsonb_to_record(d.binding||p||
    CASE WHEN p ? 'observed_offset_seconds' THEN jsonb_build_object('observed_at',
     now()+(p->>'observed_offset_seconds')::int*interval '1 second') ELSE '{}'::jsonb END)
    f(epoch text,protocol text,mac text,ip text,sensor_id text,site text,domain text,vlan text,
      vrf text,interface_name text,address_binding boolean,withdrawn boolean,
      observed_at timestamptz,valid_until timestamptz)
  )
  SELECT identity.mac FROM (SELECT d.signal||scenario.signal_patch||
   CASE WHEN scenario.signal_patch ? 'observed_offset_seconds' THEN jsonb_build_object('observed',
    now()+(scenario.signal_patch->>'observed_offset_seconds')::int*interval '1 second') ELSE '{}'::jsonb END AS association) v
  /* MAC_LATERAL */
 ) actual ON true
)
SELECT id,expected,mac FROM resolved ORDER BY id
