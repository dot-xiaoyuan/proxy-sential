package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
)

// CoverageReport counts addresses from the bounded discovery index. A /24 is
// an observation bucket, not a claim about the campus routing configuration.
type CoverageReport struct {
	AsOf                    time.Time    `json:"as_of"`
	IdentityAsOf            *time.Time   `json:"identity_as_of,omitempty"`
	IdentityStatus          string       `json:"identity_status,omitempty"`
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
	Identified              *int64       `json:"identified,omitempty"`
	DumbTerminals           *int64       `json:"dumb_terminals,omitempty"`
	IdentityTotal           *int64       `json:"identity_total,omitempty"`
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
	at := time.Now().UTC()
	out := CoverageReport{AsOf: at}
	var metadata IndexedDeviceMetadata
	var identityTimedOut bool
	group, readCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		identityCtx, cancel := context.WithTimeout(readCtx, 14*time.Second)
		defer cancel()
		var err error
		metadata, err = r.DevicesIndexedMetadata(identityCtx, DeviceQuery{Mode: "passive", Window: window, SnapshotAt: at, SkipOverview: true})
		if errors.Is(identityCtx.Err(), context.DeadlineExceeded) && readCtx.Err() == nil {
			identityTimedOut = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("coverage discovery identities: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		// Count only device-side bindings for MAC and IP/MAC. Other protocol
		// endpoints can expose a routed next-hop MAC.
		from := at.Add(-window)
		if err := coverageAddressCounts(readCtx, r.DB, sensor, from, at, &out); err != nil {
			return fmt.Errorf("coverage address counts: %w", err)
		}
		if err := coverageEvidenceCounts(readCtx, r.DB, sensor, from, at, &out); err != nil {
			return fmt.Errorf("coverage evidence counts: %w", err)
		}
		var err error
		out.MirrorFunnel, err = mirrorFunnelCounts(readCtx, r.DB, sensor, window)
		return err
	})
	if err := group.Wait(); err != nil {
		return CoverageReport{}, err
	}
	out.Window = indexedWindowLabel(window)
	if identityTimedOut {
		out.IdentityStatus = "timeout"
		return out, nil
	}
	out.IdentityAsOf = &metadata.AsOf
	out.Identified, out.IdentityTotal = &metadata.Identified, &metadata.Total
	var dumbTerminals int64
	for _, item := range metadata.Types {
		if dumbHardwareTypes[item.DeviceType] {
			dumbTerminals += item.Count
		}
	}
	out.DumbTerminals = &dumbTerminals
	return out, nil
}

// Evidence buckets partition IPv4 addresses with current-window device
// observations. They are address counts, not physical device counts. A typed
// address may have historical product evidence even if its latest observation
// contains only ARP; origin buckets are therefore reported only for untyped
// addresses with a hardware identity.
func coverageEvidenceCounts(ctx context.Context, db *sql.DB, sensor string, from, until time.Time, out *CoverageReport) error {
	// PostgreSQL underestimates the JSON IPv4 filter. Partitioning by device key
	// avoids scanning all in-window hardware keys for every matching observation.
	const statement = `WITH by_device AS (
 SELECT device_key,NULL::text ip,NULL::text origin,NULL::timestamptz observed_at,
  true hardware,hardware_type_status='identified' typed
 FROM passive_hardware_current
 WHERE sensor_id=$1 AND last_seen>=$2 AND last_seen<$3
 UNION ALL
 SELECT l.device_key,l.data->>'ip',l.origin,l.observed_at,false,false
 FROM discovery_observation_latest l
 WHERE l.data->>'node'=$1 AND l.observed_at>=$2 AND l.observed_at<$3
  AND NOT l.withdrawn
  AND l.data->>'ip' ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
), classified AS (
 SELECT ip,origin,observed_at,bool_or(hardware) OVER device has_identity,
  bool_or(typed) OVER device typed
 FROM by_device WINDOW device AS (PARTITION BY device_key)
), per_ip AS (
 SELECT ip,bool_or(has_identity) has_identity,bool_or(typed) typed,
  bool_or(origin='dhcp') dhcp,
  bool_or(origin IN ('snmp','http_device','tls_device','dns_sd','ssdp','sadp','rtsp','sip','ws_discovery')) app,
  bool_and(origin IN ('arp','ttl','ndp')) network_only,
  max(observed_at) latest
 FROM classified WHERE ip IS NOT NULL GROUP BY ip
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
), scoped AS MATERIALIZED (
 SELECT ip,mac,sensor,site,domain,vlan,vrf,v4,bool_or(valid_until>$3) valid
 FROM addresses WHERE trusted_pair GROUP BY ip,mac,sensor,site,domain,vlan,vrf,v4
), ipv4_pairs AS MATERIALIZED (
 SELECT ip,mac,count(*) scopes,bool_or(vlan='') blank_vlan,bool_or(vlan<>'') filled_vlan
 FROM scoped WHERE v4 GROUP BY ip,mac
)
SELECT count(DISTINCT split_part(ip,'.',1)||'.'||split_part(ip,'.',2)||'.'||split_part(ip,'.',3)) FILTER(WHERE v4),
 count(DISTINCT ip) FILTER(WHERE v4), count(DISTINCT ip) FILTER(WHERE v6),
 (SELECT count(DISTINCT mac) FROM scoped),
 (SELECT count(*) FROM scoped),
 (SELECT count(*) FROM (SELECT DISTINCT sensor,site,domain,vlan,vrf,mac FROM scoped) unique_scoped_macs),
 (SELECT count(DISTINCT ip) FROM ipv4_pairs),
 (SELECT count(*) FROM ipv4_pairs),
 (SELECT count(*) FROM scoped WHERE v4 AND valid),
 (SELECT count(*) FROM (SELECT ip FROM ipv4_pairs GROUP BY ip HAVING count(*)>1) multi_mac),
 (SELECT count(*) FROM ipv4_pairs WHERE scopes>1),
 (SELECT count(*) FROM ipv4_pairs WHERE blank_vlan AND filled_vlan)
FROM addresses`
	return db.QueryRowContext(ctx, statement, sensor, from, until).Scan(
		&out.Subnet24, &out.IPv4, &out.IPv6, &out.MAC, &out.IPMACPairs, &out.ScopedMAC,
		&out.IPv4WithMAC, &out.IPMACUniquePairs, &out.IPMACValidScopedPairs,
		&out.MultiMACIPv4, &out.MultiScopeIPMACPairs, &out.BlankAndFilledVLANPairs,
	)
}
