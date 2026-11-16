package discovery

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CoverageReport counts addresses from the bounded discovery index. A /24 is
// an observation bucket, not a claim about the campus routing configuration.
type CoverageReport struct {
	AsOf                    time.Time    `json:"as_of"`
	IdentityAsOf            time.Time    `json:"identity_as_of"`
	Window                  string       `json:"window"`
	Subnet24                int64        `json:"subnet24"`
	IPv4                    int64        `json:"ipv4"`
	IPv6                    int64        `json:"ipv6"`
	MAC                     int64        `json:"mac"`
	IPMACPairs              int64        `json:"ip_mac_pairs"`
	IPv4WithMAC             int64        `json:"ipv4_with_mac"`
	IPMACUniquePairs        int64        `json:"ip_mac_unique_pairs"`
	IPMACValidScopedPairs   int64        `json:"ip_mac_valid_scoped_pairs"`
	MultiMACIPv4            int64        `json:"multi_mac_ipv4"`
	MultiScopeIPMACPairs    int64        `json:"multi_scope_ip_mac_pairs"`
	BlankAndFilledVLANPairs int64        `json:"blank_and_filled_vlan_pairs"`
	ScopedMAC               int64        `json:"scoped_mac"`
	Identified              int64        `json:"identified"`
	DumbTerminals           int64        `json:"dumb_terminals"`
	IdentityTotal           int64        `json:"identity_total"`
	DiagnosticAsOf          *time.Time   `json:"diagnostic_as_of,omitempty"`
	TypedIPv4               int64        `json:"typed_ipv4"`
	IdentityNoTypeIPv4      int64        `json:"identity_no_type_ipv4"`
	NoIdentityIPv4          int64        `json:"no_identity_ipv4"`
	UntypedNetworkOnlyIPv4  int64        `json:"untyped_network_only_ipv4"`
	UntypedDHCPOnlyIPv4     int64        `json:"untyped_dhcp_only_ipv4"`
	UntypedApplicationIPv4  int64        `json:"untyped_application_ipv4"`
	UntypedOtherIPv4        int64        `json:"untyped_other_ipv4"`
	MirrorFunnel            MirrorFunnel `json:"mirror_funnel"`
}

var dumbHardwareTypes = map[string]bool{
	"printer": true, "scanner": true, "camera": true, "recorder": true,
	"access_control": true, "voip_phone": true, "media_player": true,
	"media_device": true, "display": true, "tv": true, "ups": true,
	"pdu": true, "environment_monitor": true,
}

func (r Repository) DiscoveryCoverageReport(ctx context.Context, sensor string, window time.Duration) (CoverageReport, error) {
	if !r.HardwareV2 || r.DB == nil || sensor == "" || window < 10*time.Minute || window > 30*24*time.Hour {
		return CoverageReport{}, fmt.Errorf("coverage report requires passive hardware reader, sensor and bounded window")
	}
	metadata, err := r.DevicesIndexedMetadata(ctx, DeviceQuery{Mode: "passive", Window: window})
	if err != nil {
		return CoverageReport{}, err
	}
	out := CoverageReport{AsOf: time.Now().UTC(), IdentityAsOf: metadata.AsOf, Window: metadata.Window, Identified: metadata.Identified, IdentityTotal: metadata.Total}
	for _, item := range metadata.Types {
		if dumbHardwareTypes[item.DeviceType] {
			out.DumbTerminals += item.Count
		}
	}
	// Count only device-side address bindings for MAC and IP/MAC. Other protocol
	// endpoints can expose a routed next-hop MAC and must not inflate these.
	err = coverageAddressCounts(ctx, r.DB, sensor, out.AsOf.Add(-window), out.AsOf, &out)
	if err == nil {
		err = coverageEvidenceCounts(ctx, r.DB, sensor, out.AsOf.Add(-window), out.AsOf, &out)
	}
	if err == nil {
		out.MirrorFunnel, err = mirrorFunnelCounts(ctx, r.DB, sensor, window)
	}
	return out, err
}

// Evidence buckets partition IPv4 addresses with current-window device
// observations. They are address counts, not physical device counts. A typed
// address may have historical product evidence even if its latest observation
// contains only ARP; origin buckets are therefore reported only for untyped
// addresses with a hardware identity.
func coverageEvidenceCounts(ctx context.Context, db *sql.DB, sensor string, from, until time.Time, out *CoverageReport) error {
	const statement = `WITH hw AS MATERIALIZED (
 SELECT device_key,bool_or(hardware_type_status='identified') typed
 FROM passive_hardware_current
 WHERE sensor_id=$1 AND last_seen>=$2 AND last_seen<$3 GROUP BY device_key
), per_ip AS (
 SELECT l.data->>'ip' ip,bool_or(hw.device_key IS NOT NULL) has_identity,
  bool_or(coalesce(hw.typed,false)) typed,
  bool_or(l.origin='dhcp') dhcp,
  bool_or(l.origin IN ('snmp','http_device','tls_device','dns_sd','ssdp','sadp','rtsp','sip','ws_discovery')) app,
  bool_and(l.origin IN ('arp','ttl','ndp')) network_only,
  max(l.observed_at) latest
 FROM discovery_observation_latest l LEFT JOIN hw ON hw.device_key=l.device_key
 WHERE l.data->>'node'=$1 AND l.observed_at>=$2 AND l.observed_at<$3
  AND NOT l.withdrawn
  AND l.data->>'ip' ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
 GROUP BY l.data->>'ip'
)
SELECT count(*) FILTER(WHERE typed),
 count(*) FILTER(WHERE has_identity AND NOT typed),
 count(*) FILTER(WHERE NOT has_identity),
 count(*) FILTER(WHERE has_identity AND NOT typed AND network_only),
 count(*) FILTER(WHERE has_identity AND NOT typed AND dhcp AND NOT app),
 count(*) FILTER(WHERE has_identity AND NOT typed AND app),
 count(*) FILTER(WHERE has_identity AND NOT typed AND NOT network_only AND NOT dhcp AND NOT app),
 max(latest)
FROM per_ip`
	var latest sql.NullTime
	err := db.QueryRowContext(ctx, statement, sensor, from, until).Scan(
		&out.TypedIPv4, &out.IdentityNoTypeIPv4, &out.NoIdentityIPv4,
		&out.UntypedNetworkOnlyIPv4, &out.UntypedDHCPOnlyIPv4,
		&out.UntypedApplicationIPv4, &out.UntypedOtherIPv4, &latest,
	)
	if latest.Valid {
		out.DiagnosticAsOf = &latest.Time
	}
	return err
}

func coverageAddressCounts(ctx context.Context, db *sql.DB, sensor string, from, until time.Time, out *CoverageReport) error {
	const statement = `WITH observed AS MATERIALIZED (
 SELECT l.data->>'ip' ip,lower(coalesce(l.data->>'mac','')) mac,l.valid_until,
  coalesce(l.data->>'node','') sensor,coalesce(l.data->>'site','') site,
  coalesce(l.data->>'domain','') domain,coalesce(l.data->>'vlan','') vlan,
  coalesce(l.data->>'vrf','') vrf,
  (l.origin IN ('arp','dhcp') OR
   (l.origin='sadp' AND l.data->'evidence'->'payload'->>'identity_status' IN ('direct_l2','arp_binding')) OR
   (l.origin='dns_sd' AND l.data->'evidence'->'payload'->>'l2_source_mac_direct'='true')) binding
 FROM discovery_observation_latest l
 WHERE l.observed_at>=$2 AND l.observed_at<=$3 AND NOT l.withdrawn
  AND l.data->>'node'=$1
), addresses AS (
 SELECT *,ip ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' v4,
  ip LIKE '%:%' v6,
  binding AND mac ~ '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$'
   AND mac<>'00:00:00:00:00:00' AND ip<>'' trusted_pair
 FROM observed
), trusted_ipv4 AS MATERIALIZED (
 SELECT ip,mac,vlan,valid_until,
  jsonb_build_array(ip,mac)::text raw_pair,
  jsonb_build_array(sensor,site,domain,vlan,vrf,ip,mac)::text scoped_pair
 FROM addresses WHERE v4 AND trusted_pair
)
SELECT count(DISTINCT split_part(ip,'.',1)||'.'||split_part(ip,'.',2)||'.'||split_part(ip,'.',3)) FILTER(WHERE v4),
 count(DISTINCT ip) FILTER(WHERE v4), count(DISTINCT ip) FILTER(WHERE v6),
 count(DISTINCT mac) FILTER(WHERE trusted_pair),
 count(DISTINCT jsonb_build_array(sensor,site,domain,vlan,vrf,ip,mac)::text) FILTER(WHERE trusted_pair),
 count(DISTINCT jsonb_build_array(sensor,site,domain,vlan,vrf,mac)::text) FILTER(WHERE trusted_pair),
 (SELECT count(DISTINCT ip) FROM trusted_ipv4),
 (SELECT count(DISTINCT raw_pair) FROM trusted_ipv4),
 (SELECT count(DISTINCT scoped_pair) FROM trusted_ipv4 WHERE valid_until>$3),
 (SELECT count(*) FROM (SELECT ip FROM trusted_ipv4 GROUP BY ip HAVING count(DISTINCT mac)>1) multi_mac),
 (SELECT count(*) FROM (SELECT raw_pair FROM trusted_ipv4 GROUP BY raw_pair HAVING count(DISTINCT scoped_pair)>1) multi_scope),
 (SELECT count(*) FROM (SELECT raw_pair FROM trusted_ipv4 GROUP BY raw_pair HAVING bool_or(vlan='') AND bool_or(vlan<>'')) mixed_vlan)
FROM addresses`
	return db.QueryRowContext(ctx, statement, sensor, from, until).Scan(
		&out.Subnet24, &out.IPv4, &out.IPv6, &out.MAC, &out.IPMACPairs, &out.ScopedMAC,
		&out.IPv4WithMAC, &out.IPMACUniquePairs, &out.IPMACValidScopedPairs,
		&out.MultiMACIPv4, &out.MultiScopeIPMACPairs, &out.BlankAndFilledVLANPairs,
	)
}
