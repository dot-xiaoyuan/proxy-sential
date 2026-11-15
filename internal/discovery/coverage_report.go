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
	AsOf          time.Time `json:"as_of"`
	IdentityAsOf  time.Time `json:"identity_as_of"`
	Window        string    `json:"window"`
	Subnet24      int64     `json:"subnet24"`
	IPv4          int64     `json:"ipv4"`
	IPv6          int64     `json:"ipv6"`
	MAC           int64     `json:"mac"`
	IPMACPairs    int64     `json:"ip_mac_pairs"`
	ScopedMAC     int64     `json:"scoped_mac"`
	Identified    int64     `json:"identified"`
	DumbTerminals int64     `json:"dumb_terminals"`
	IdentityTotal int64     `json:"identity_total"`
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
	return out, err
}

func coverageAddressCounts(ctx context.Context, db *sql.DB, sensor string, from, until time.Time, out *CoverageReport) error {
	const statement = `WITH observed AS MATERIALIZED (
 SELECT l.data->>'ip' ip,lower(coalesce(l.data->>'mac','')) mac,
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
)
SELECT count(DISTINCT split_part(ip,'.',1)||'.'||split_part(ip,'.',2)||'.'||split_part(ip,'.',3)) FILTER(WHERE v4),
 count(DISTINCT ip) FILTER(WHERE v4), count(DISTINCT ip) FILTER(WHERE v6),
 count(DISTINCT mac) FILTER(WHERE trusted_pair),
 count(DISTINCT jsonb_build_array(sensor,site,domain,vlan,vrf,ip,mac)::text) FILTER(WHERE trusted_pair),
 count(DISTINCT jsonb_build_array(sensor,site,domain,vlan,vrf,mac)::text) FILTER(WHERE trusted_pair)
FROM addresses`
	return db.QueryRowContext(ctx, statement, sensor, from, until).Scan(&out.Subnet24, &out.IPv4, &out.IPv6, &out.MAC, &out.IPMACPairs, &out.ScopedMAC)
}
