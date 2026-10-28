// Package streamidentity resolves compact current protocol facts without
// consulting raw events or the retired legacy lease projection.
package streamidentity

// FactContextSQL projects only association metadata from a compact fact f.
// It deliberately excludes product values and the raw event body.
const FactContextSQL = `jsonb_build_object('protocol',f.protocol,'mac',f.mac,'ip',f.ip,
 'sensor',f.sensor_id,'site',f.site,'domain',f.domain,'vlan',f.vlan,'vrf',f.vrf,
 'interface',f.interface_name,'observed',f.observed_at)`

// MACLateralSQL expects v.association with protocol, mac, ip, sensor, site,
// domain, vlan, vrf, interface and observed. It returns identity.mac.
// DHCP ACK/reply/release carries a protocol-level client MAC. Other IP signals
// require a unique active binding in the identical physical scope, covering
// both the observation and the current instant. A renewal seen after a service
// observation is conservatively insufficient; first_observed_at cannot prove
// continuity across a MAC reassignment. Withdrawn/expired/closed facts never
// establish ownership. Ethernet sender MACs are not an ownership fallback.
// At most 65 narrow binding rows are read; saturation fails closed.
const MACLateralSQL = `LEFT JOIN LATERAL (
 SELECT CASE
 WHEN COALESCE(v.association->>'mac','')<>'' AND (
   COALESCE(v.association->>'ip','')='' OR v.association->>'protocol' IN ('dhcp','dhcpv6'))
 THEN lower(v.association->>'mac')
 ELSE (
  SELECT CASE WHEN count(*)<65 AND count(DISTINCT b.mac)=1
   AND (COALESCE(v.association->>'mac','')='' OR min(b.mac)=lower(v.association->>'mac'))
   THEN min(b.mac) END
  FROM (
   SELECT b.mac FROM stream_source_cutovers c
   JOIN stream_discovery_facts b ON b.epoch=c.epoch
   WHERE c.state='active' AND COALESCE(v.association->>'ip','')<>'' AND b.ip<>'' AND b.ip=v.association->>'ip'
    AND b.address_binding AND b.protocol IN ('dhcp','dhcpv6','arp','ndp') AND b.mac<>'' AND NOT b.withdrawn
    AND b.sensor_id=v.association->>'sensor' AND b.site=v.association->>'site'
    AND b.domain=v.association->>'domain' AND b.vlan=v.association->>'vlan'
    AND b.vrf=v.association->>'vrf' AND b.interface_name=v.association->>'interface'
    AND b.observed_at<=(v.association->>'observed')::timestamptz AND b.observed_at<=now()
    AND b.valid_until>(v.association->>'observed')::timestamptz AND b.valid_until>now()
   LIMIT 65
  ) b
 ) END AS mac
) identity ON true`
