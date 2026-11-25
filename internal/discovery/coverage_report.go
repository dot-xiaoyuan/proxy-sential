package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
)

type CoverageBindingFreshness struct {
	Current   int64 `json:"current"`
	Expired   int64 `json:"expired"`
	Uncertain int64 `json:"uncertain"`
	NoBinding int64 `json:"no_binding"`
}

type CoverageIPv4TypeReview struct {
	WithdrawnConfirmation int64 `json:"withdrawn_confirmation"`
	Conflict              int64 `json:"conflict"`
	ConfirmedInactive     int64 `json:"confirmed_inactive"`
}

type CoverageIPv4PendingRow struct {
	Status         string `json:"status"`
	NetworkOnly    int64  `json:"network_only"`
	DHCPOnly       int64  `json:"dhcp_only"`
	DeviceProtocol int64  `json:"device_protocol"`
	Other          int64  `json:"other"`
}

// CoverageReport counts addresses from the bounded discovery index. A /24 is
// an observation bucket, not a claim about the campus routing configuration.
type CoverageReport struct {
	PlannedIPv4             *PlannedIPv4Report `json:"planned_ipv4,omitempty"`
	HardwareTrend           *HardwareTrend     `json:"hardware_trend,omitempty"`
	Publication             *ReportPublication `json:"publication,omitempty"`
	AsOf                    time.Time          `json:"as_of"`
	IdentityAsOf            *time.Time         `json:"identity_as_of,omitempty"`
	IdentityStatus          string             `json:"identity_status,omitempty"`
	Window                  string             `json:"window"`
	Subnet24                int64              `json:"subnet24"`
	IPv4                    int64              `json:"ipv4"`
	IPv6                    int64              `json:"ipv6"`
	MAC                     int64              `json:"mac"`
	IPMACPairs              int64              `json:"ip_mac_pairs"`
	IPv4WithMAC             int64              `json:"ipv4_with_mac"`
	IPMACUniquePairs        int64              `json:"ip_mac_unique_pairs"`
	IPMACValidScopedPairs   int64              `json:"ip_mac_valid_scoped_pairs"`
	MultiMACIPv4            int64              `json:"multi_mac_ipv4"`
	MultiScopeIPMACPairs    int64              `json:"multi_scope_ip_mac_pairs"`
	BlankAndFilledVLANPairs int64              `json:"blank_and_filled_vlan_pairs"`
	ScopedMAC               int64              `json:"scoped_mac"`
	Identified              *int64             `json:"identified,omitempty"`
	DumbTerminals           *int64             `json:"dumb_terminals,omitempty"`
	IdentityTotal           *int64             `json:"identity_total,omitempty"`
	DiagnosticAsOf          *time.Time         `json:"diagnostic_as_of,omitempty"`
	TypedIPv4               int64              `json:"typed_ipv4"`
	IdentityNoTypeIPv4      int64              `json:"identity_no_type_ipv4"`
	NoIdentityIPv4          int64              `json:"no_identity_ipv4"`
	UntypedNetworkOnlyIPv4  int64              `json:"untyped_network_only_ipv4"`
	UntypedDHCPOnlyIPv4     int64              `json:"untyped_dhcp_only_ipv4"`
	UntypedApplicationIPv4  int64              `json:"untyped_application_ipv4"`
	UntypedOtherIPv4        int64              `json:"untyped_other_ipv4"`
	RevokedTypeIPv4         int64              `json:"revoked_type_ipv4"`
	MirrorFunnel            MirrorFunnel       `json:"mirror_funnel"`

	IPv4BindingFreshness *CoverageBindingFreshness `json:"ipv4_binding_freshness,omitempty"`
	IPv6BindingFreshness *CoverageBindingFreshness `json:"ipv6_binding_freshness,omitempty"`
	IPv4TypeReview       *CoverageIPv4TypeReview   `json:"ipv4_type_review,omitempty"`
	ProfileCandidates    *int64                    `json:"profile_candidate_identities,omitempty"`
	IPv4Pending          []CoverageIPv4PendingRow  `json:"ipv4_pending,omitempty"`
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
	if structuredReadEnabled("coverage") {
		if err := checkStructuredRead(ctx, r.DB); err != nil {
			return CoverageReport{}, err
		}
	}
	out := CoverageReport{AsOf: at}
	group, readCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		identityCtx, cancel := context.WithDeadline(readCtx, at.Add(14*time.Second))
		err := coverageIdentityAndPendingCounts(identityCtx, r.DB, sensor, window, at, &out)
		timedOut := errors.Is(identityCtx.Err(), context.DeadlineExceeded) && readCtx.Err() == nil
		cancel()
		if timedOut {
			out.IdentityStatus = "timeout"
			if err := coverageEvidenceCounts(readCtx, r.DB, sensor, at.Add(-window), at, &out); err != nil {
				return fmt.Errorf("coverage evidence counts: %w", err)
			}
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
		var err error
		out.MirrorFunnel, err = mirrorFunnelCounts(readCtx, r.DB, sensor, window)
		return err
	})
	if err := group.Wait(); err != nil {
		return CoverageReport{}, err
	}
	out.Window = indexedWindowLabel(window)
	if out.IdentityAsOf != nil {
		if fresh := r.PassiveDiscoveryFreshness(ctx); fresh != nil {
			if cutoff, ok := fresh["cursor_at"].(time.Time); ok && !cutoff.IsZero() {
				out.IdentityAsOf = &cutoff
			}
		}
	}
	return out, nil
}

// Evidence buckets partition IPv4 addresses with current-window device
// observations. They are address counts, not physical device counts. A typed
// address may have historical product evidence even if its latest observation
// contains only ARP; origin buckets are therefore reported only for untyped
// addresses with a hardware identity.
type coverageQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func coverageEvidenceCounts(ctx context.Context, db coverageQueryRower, sensor string, from, until time.Time, out *CoverageReport) error {
	return db.QueryRowContext(ctx, "WITH "+coveragePerIPSQL("$1", "$2", "$3", "", "false")+coverageEvidenceSelectSQL, sensor, from, until).
		Scan(coverageEvidenceDestinations(out)...)
}

func coverageEvidenceDestinations(out *CoverageReport) []any {
	out.IPv4TypeReview = &CoverageIPv4TypeReview{}
	return []any{
		&out.TypedIPv4, &out.IdentityNoTypeIPv4, &out.NoIdentityIPv4,
		&out.UntypedNetworkOnlyIPv4, &out.UntypedDHCPOnlyIPv4,
		&out.UntypedApplicationIPv4, &out.UntypedOtherIPv4, &out.RevokedTypeIPv4,
		&out.IPv4TypeReview.WithdrawnConfirmation, &out.IPv4TypeReview.Conflict,
		&out.IPv4TypeReview.ConfirmedInactive, &out.DiagnosticAsOf,
	}
}

const coverageEvidenceSelectSQL = `SELECT count(*) FILTER(WHERE typed),
 count(*) FILTER(WHERE has_identity AND NOT typed),
 count(*) FILTER(WHERE NOT has_identity),
 count(*) FILTER(WHERE has_identity AND NOT typed AND network_only),
 count(*) FILTER(WHERE has_identity AND NOT typed AND dhcp AND NOT app),
 count(*) FILTER(WHERE has_identity AND NOT typed AND app),
 count(*) FILTER(WHERE has_identity AND NOT typed AND NOT network_only AND NOT dhcp AND NOT app),
 count(*) FILTER(WHERE has_identity AND NOT typed AND revoked_type),
 count(*) FILTER(WHERE NOT typed AND withdrawn_confirmation),
 count(*) FILTER(WHERE NOT typed AND NOT withdrawn_confirmation AND type_conflict),
 count(*) FILTER(WHERE typed AND NOT typed_active),
 max(latest)
FROM per_ip`

func coveragePerIPSQL(sensor, from, until, profileJoin, hasProfile string) string {
	// PostgreSQL underestimates the JSON IPv4 filter. Partitioning by device key
	// avoids scanning all in-window hardware keys for every matching observation.
	observations := fmt.Sprintf(` SELECT l.device_key,l.data->>'ip',l.origin,l.observed_at,false,false,false,false,false,false,false
 FROM discovery_observation_latest l
 WHERE l.data->>'node'=%[1]s AND l.observed_at>=%[2]s AND l.observed_at<%[3]s
  AND NOT l.withdrawn
  AND l.data->>'ip' ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'`, sensor, from, until)
	if structuredReadEnabled("coverage") {
		observations = structuredCoverageObservations(sensor, from, until)
	}
	return fmt.Sprintf(`by_device AS (
 SELECT h.device_key,NULL::text ip,NULL::text origin,NULL::timestamptz observed_at,
  true hardware,hardware_type_status='identified' typed,hardware_type_status='revoked' revoked_type,
  hardware_type_status='revoked' AND hardware_type<>'' withdrawn_confirmation,
  hardware_type_status='conflict' type_conflict,
  hardware_type_status='identified' AND active_until>%[3]s typed_active,
  %[5]s has_profile
 FROM passive_hardware_current h %[4]s
 WHERE h.sensor_id=%[1]s AND h.last_seen>=%[2]s AND h.last_seen<%[3]s
 UNION ALL
%[6]s
), classified AS (
 SELECT ip,origin,observed_at,bool_or(hardware) OVER device has_identity,
  bool_or(typed) OVER device typed,bool_or(revoked_type) OVER device revoked_type,
  bool_or(withdrawn_confirmation) OVER device withdrawn_confirmation,
  bool_or(type_conflict) OVER device type_conflict,bool_or(typed_active) OVER device typed_active,
  bool_or(has_profile) OVER device has_profile
 FROM by_device WINDOW device AS (PARTITION BY device_key)
), per_ip AS (
 SELECT ip,bool_or(has_identity) has_identity,bool_or(typed) typed,bool_or(revoked_type) revoked_type,
  bool_or(withdrawn_confirmation) withdrawn_confirmation,bool_or(type_conflict) type_conflict,bool_or(typed_active) typed_active,
  bool_or(has_profile) has_profile,
  bool_or(origin='dhcp') dhcp,
  bool_or(origin IN ('snmp','http_device','tls_device','dns_sd','ssdp','sadp','rtsp','sip','ws_discovery')) app,
  bool_and(origin IN ('arp','ttl','ndp')) network_only,
  max(observed_at) latest
 FROM classified WHERE ip IS NOT NULL GROUP BY ip
)
`, sensor, from, until, profileJoin, hasProfile, observations)
}

func coverageAddressCounts(ctx context.Context, db *sql.DB, sensor string, from, until time.Time, out *CoverageReport) error {
	const statement = `WITH observed AS MATERIALIZED (
 SELECT l.data->>'ip' ip,lower(coalesce(l.data->>'mac','')) mac,l.valid_until,l.observed_at,l.withdrawn,
  coalesce(l.data->>'node','') sensor,coalesce(l.data->>'site','') site,
  coalesce(l.data->>'domain','') domain,coalesce(l.data->>'vlan','') vlan,
  coalesce(l.data->>'vrf','') vrf,
  (l.origin IN ('arp','ndp','dhcp') AND l.data->>'confidence'='confirmed'
   AND coalesce(l.data->'evidence'->'observer'->>'capture_scope_issue','')=''
   AND coalesce(l.data->'evidence'->'payload'->>'endpoint_identity_unverified','')<>'true') address_claim,
  (l.origin IN ('arp','dhcp') OR
   (l.origin='sadp' AND l.data->'evidence'->'payload'->>'identity_status' IN ('direct_l2','arp_binding')) OR
   (l.origin='dns_sd' AND l.data->'evidence'->'payload'->>'l2_source_mac_direct'='true')) binding
 FROM discovery_observation_latest l
 WHERE l.observed_at>=$2 AND l.observed_at<=$3
  AND l.data->>'node'=$1
), addresses AS (
 SELECT *,ip ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' v4,
  ip LIKE '%:%' v6,
  binding AND mac ~ '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$'
   AND mac<>'00:00:00:00:00:00' AND ip<>'' trusted_pair
 FROM observed
), scoped AS MATERIALIZED (
 SELECT ip,mac,sensor,site,domain,vlan,vrf,v4,bool_or(valid_until>$3) valid
 FROM addresses WHERE trusted_pair AND NOT withdrawn GROUP BY ip,mac,sensor,site,domain,vlan,vrf,v4
), ipv4_pairs AS MATERIALIZED (
 SELECT ip,mac,count(*) scopes,bool_or(vlan='') blank_vlan,bool_or(vlan<>'') filled_vlan
 FROM scoped WHERE v4 GROUP BY ip,mac
), claims AS (
 SELECT ip,mac,site,domain,vlan,vrf,
  max(observed_at) FILTER (WHERE NOT withdrawn) last_claim,
  max(observed_at) FILTER (WHERE NOT withdrawn AND valid_until>$3) last_live,
  max(observed_at) FILTER (WHERE withdrawn) last_withdrawal
 FROM addresses
 WHERE address_claim AND site<>'' AND domain<>'' AND (v4 OR v6)
  AND mac ~ '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$' AND mac<>'00:00:00:00:00:00'
 GROUP BY ip,mac,site,domain,vlan,vrf
), scope_freshness AS (
 SELECT ip,count(*) FILTER(WHERE last_live IS NOT NULL AND (last_withdrawal IS NULL OR last_live>last_withdrawal)) live_count,
  bool_or(last_withdrawal IS NOT NULL AND (last_claim IS NULL OR last_withdrawal>=last_claim)) withdrawn
 FROM claims GROUP BY ip,site,domain,vlan,vrf
), ip_freshness AS (
 SELECT ip,CASE WHEN bool_or(live_count=1) THEN 'current'
  WHEN bool_or(live_count>1 OR withdrawn) THEN 'uncertain' ELSE 'expired' END freshness
 FROM scope_freshness GROUP BY ip
), observed_ips AS MATERIALIZED (
 SELECT DISTINCT ip,v4,v6 FROM addresses WHERE NOT withdrawn AND (v4 OR v6)
), freshness_counts AS (
 SELECT count(*) FILTER(WHERE i.v4 AND f.freshness='current') current_v4,
  count(*) FILTER(WHERE i.v4 AND f.freshness='expired') expired_v4,
  count(*) FILTER(WHERE i.v4 AND f.freshness='uncertain') uncertain_v4,
  count(*) FILTER(WHERE i.v4 AND f.ip IS NULL) no_binding_v4,
  count(*) FILTER(WHERE i.v6 AND f.freshness='current') current_v6,
  count(*) FILTER(WHERE i.v6 AND f.freshness='expired') expired_v6,
  count(*) FILTER(WHERE i.v6 AND f.freshness='uncertain') uncertain_v6,
  count(*) FILTER(WHERE i.v6 AND f.ip IS NULL) no_binding_v6
 FROM observed_ips i LEFT JOIN ip_freshness f USING(ip)
)
SELECT (SELECT count(DISTINCT split_part(ip,'.',1)||'.'||split_part(ip,'.',2)||'.'||split_part(ip,'.',3)) FROM observed_ips WHERE v4),
 (SELECT count(*) FROM observed_ips WHERE v4), (SELECT count(*) FROM observed_ips WHERE v6),
 (SELECT count(DISTINCT mac) FROM scoped),
 (SELECT count(*) FROM scoped),
 (SELECT count(*) FROM (SELECT DISTINCT sensor,site,domain,vlan,vrf,mac FROM scoped) unique_scoped_macs),
 (SELECT count(DISTINCT ip) FROM ipv4_pairs),
 (SELECT count(*) FROM ipv4_pairs),
 (SELECT count(*) FROM scoped WHERE v4 AND valid),
 (SELECT count(*) FROM (SELECT ip FROM ipv4_pairs GROUP BY ip HAVING count(*)>1) multi_mac),
 (SELECT count(*) FROM ipv4_pairs WHERE scopes>1),
 (SELECT count(*) FROM ipv4_pairs WHERE blank_vlan AND filled_vlan),
 current_v4,expired_v4,uncertain_v4,no_binding_v4,current_v6,expired_v6,uncertain_v6,no_binding_v6
FROM freshness_counts`
	var v4, v6 CoverageBindingFreshness
	err := db.QueryRowContext(ctx, statement, sensor, from, until).Scan(
		&out.Subnet24, &out.IPv4, &out.IPv6, &out.MAC, &out.IPMACPairs, &out.ScopedMAC,
		&out.IPv4WithMAC, &out.IPMACUniquePairs, &out.IPMACValidScopedPairs,
		&out.MultiMACIPv4, &out.MultiScopeIPMACPairs, &out.BlankAndFilledVLANPairs,
		&v4.Current, &v4.Expired, &v4.Uncertain, &v4.NoBinding,
		&v6.Current, &v6.Expired, &v6.Uncertain, &v6.NoBinding,
	)
	if err == nil {
		out.IPv4BindingFreshness, out.IPv6BindingFreshness = &v4, &v6
	}
	return err
}
