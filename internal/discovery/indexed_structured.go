package discovery

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Reads are switched independently after adoption and same-snapshot comparison.
func structuredReadEnabled(surface string) bool {
	for _, enabled := range strings.Split(os.Getenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS"), ",") {
		if enabled == surface {
			return true
		}
	}
	return false
}

func structuredSourceSQL(query DeviceQuery, baseWhere []string) string {
	// Only the observation-level filters run before grouping.
	predicates := strings.NewReplacer(
		"NOT l.withdrawn", "true",
		"coalesce(data->>'domain','')", "l.access_domain",
		"coalesce(data->>'vlan','')", "l.vlan",
		"coalesce(l.data->>'mac','')", "l.raw_mac",
		"l.data->>'mac'", "l.raw_mac",
	).Replace(strings.Join(baseWhere, " AND "))
	caps := "'[]'::jsonb"
	if query.Capability != "" || query.View == "iot" {
		caps = "l.capabilities"
	}
	dhcp := "''::text"
	if query.DeviceType != "" || query.includeCandidateTypes || query.View == "iot" || query.Capability == "dumb" {
		dhcp = "CASE WHEN l.valid_until>now() AND l.origin IN ('dhcp_client','dhcp') THEN l.dhcp_type ELSE '' END"
	}
	return ` SELECT l.ctid observation_tid,l.id,l.device_key,l.origin,l.observed_at,l.valid_until,l.sensor_id,l.site_id,l.access_domain,l.vlan,l.vrf,l.raw_mac,l.raw_ip,
 l.scope_valid capture_scope_valid,l.source_campus,lower(l.raw_ip) search_ip,lower(l.raw_mac) search_mac,
 lower(l.name) search_name,lower(l.device_type) search_device_type,lower(l.manufacturer) search_manufacturer,lower(l.model) search_model,
 ` + caps + ` observation_capabilities,
 CASE WHEN l.valid_until>now() AND l.product_status='identified' THEN l.product_type ELSE '' END product_type,
 (l.valid_until>now() AND l.product_status IN ('identified','no_type_match','conflict')) product_evidence,
 ` + dhcp + ` dhcp_candidate_type,
 (l.valid_until>now() AND l.strong_service AND l.scope_valid) service_clue_valid,l.base_identity
 FROM discovery_list_observation l WHERE ` + predicates
}

// The default views can use per-identity window summaries. User-defined
// combinations still run their predicates over the same structured facts.
func cachedGroupWindow(q DeviceQuery) int {
	if !q.structured || q.Mode != "passive" || q.groupPageRows || q.View != "" || q.Search != "" || q.Protocol != "" || q.State != "" || q.Domain != "" || q.VLAN != "" || q.DeviceType != "" || q.ReviewReason != "" || q.Category != "" || q.OSFamily != "" || q.Capability != "" || q.RandomMAC || q.Subnet != "" || q.FirstSeenWithin != 0 || !q.LastSeenFrom.IsZero() || !q.LastSeenTo.IsZero() {
		return 0
	}
	switch q.Window.Hours() {
	case 24, 168, 720:
		return int(q.Window.Hours())
	}
	return 0
}

// Pending generations are resolved from the two authoritative relations in the
// reader's own snapshot. Concurrent link corrections cannot expose stale owners.
const liveAddressLinksCTE = `, live_address_links AS MATERIALIZED (
 SELECT c.observation_id,c.endpoint_id FROM discovery_address_link_current c
 WHERE NOT EXISTS(SELECT 1 FROM discovery_address_link_dirty d WHERE d.observation_id=c.observation_id)
 UNION ALL
 SELECT i.observation_id,i.endpoint_id FROM (SELECT DISTINCT observation_id FROM discovery_address_link_dirty) d
 JOIN discovery_identity_links i USING(observation_id)
 WHERE EXISTS(SELECT 1 FROM discovery_list_observation f WHERE f.id=d.observation_id AND f.raw_mac='')
)`

func cachedGroupCTE(hours int) string {
	// Incoming address-only links or an exceptional outgoing link can merge
	// raw identity groups. Send both sides through the live membership query.
	return fmt.Sprintf(`, exceptional_links AS MATERIALIZED (
 SELECT observation_id,endpoint_id FROM discovery_identity_links
 WHERE coalesce(basis->>'mac','')='' OR lower(endpoint_id)<>'mac:'||lower(basis->>'mac')
), exceptional_members AS MATERIALIZED (
 SELECT f.base_identity,f.sensor_id,f.site_id,f.access_domain,f.vlan,f.vrf,lower(i.endpoint_id) endpoint
 FROM exceptional_links i CROSS JOIN LATERAL (
   SELECT * FROM discovery_list_observation f WHERE f.id=i.observation_id AND f.observed_at>=$1 OFFSET 0
 ) f
), exception_keys AS MATERIALIZED (
 SELECT base_identity identity_key FROM exceptional_members
 UNION
 SELECT jsonb_build_array('identity',sensor_id,site_id,access_domain,vlan,vrf,'mac',substring(endpoint FROM 5))::text
 FROM exceptional_members WHERE endpoint LIKE 'mac:%%'
 UNION
 SELECT jsonb_build_array('identity',f.sensor_id,f.site_id,f.access_domain,f.vlan,f.vrf,'mac',substring(lower(i.endpoint_id) FROM 5))::text
 FROM discovery_list_observation f JOIN discovery_identity_links i ON i.observation_id=f.id
 WHERE f.raw_mac='' AND f.observed_at>=$1 AND lower(i.endpoint_id) LIKE 'mac:%%'
 UNION
 SELECT jsonb_build_array('identity',f.sensor_id,f.site_id,f.access_domain,f.vlan,f.vrf,'mac',t.mac)::text
 FROM trusted_address t JOIN discovery_list_observation f ON f.id=t.observation_id
), cache_groups AS MATERIALIZED (
 SELECT g.* FROM discovery_list_group_current g
 WHERE hours=%d AND last_seen>=$1 AND computed_at<=least(now(),$1::timestamptz+interval '%d hours')
 AND next_change>greatest(now(),$1::timestamptz+interval '%d hours')
 AND NOT EXISTS(SELECT 1 FROM discovery_list_dirty d WHERE d.identity_key=g.identity_key)
 AND NOT EXISTS(SELECT 1 FROM exception_keys x WHERE x.identity_key=g.identity_key)
)`, hours, hours, hours)
}

func cachedGroupedSQL(q DeviceQuery, pageProfiles bool) string {
	role, join := "''::text", ""
	if !pageProfiles {
		join = " LEFT JOIN endpoint_recognition_summary p ON p.endpoint_id='mac:'||g.mac"
		conf := indexedProfileConfidenceSQL("p")
		conflict := indexedProfileConflictSQL("p")
		dhcp := "false"
		if q.includeCandidateTypes {
			dhcp = "true"
		}
		role = `CASE WHEN NOT (` + conflict + `) AND g.verified_until>now() THEN CASE
 WHEN ` + dhcp + ` AND coalesce(p.role,'')='' AND cardinality(g.dhcp_types)=1 THEN g.dhcp_types[1]
 WHEN ` + dhcp + ` AND p.role=ANY(g.dhcp_types) THEN p.role
 WHEN p.last_seen BETWEEN $1 AND now() AND ` + conf + `>=0.4 THEN coalesce(p.role,'')
 ELSE '' END ELSE '' END`
	}
	return ` UNION ALL SELECT g.identity_key,g.vlan,g.device_key,g.last_seen,''::text profile_os,g.subnets,g.product_types,
 g.has_ip,true,false,false,false,false,` + role + ` candidate_role FROM cache_groups g` + join
}

func structuredCoverageObservations(sensor, from, until string) string {
	return fmt.Sprintf(` SELECT c.device_key,c.ip,c.origin,c.last_seen,false,false,false,false,false,false,false
 FROM discovery_list_ip_current c
 WHERE c.sensor_id=%[1]s AND c.last_seen>=%[2]s AND c.last_seen<%[3]s
 AND NOT EXISTS(SELECT 1 FROM discovery_list_ip_dirty d WHERE (d.sensor_id,d.device_key,d.ip,d.origin)=(c.sensor_id,c.device_key,c.ip,c.origin))
 UNION ALL
 SELECT k.device_key,k.ip,k.origin,f.observed_at,false,false,false,false,false,false,false
 FROM (
  SELECT device_key,ip,origin FROM discovery_list_ip_dirty WHERE sensor_id=%[1]s
  UNION SELECT device_key,ip,origin FROM discovery_list_ip_current WHERE sensor_id=%[1]s AND last_seen>=%[3]s
 ) k CROSS JOIN LATERAL (
  SELECT observed_at FROM discovery_list_observation f WHERE f.sensor_id=%[1]s AND f.device_key=k.device_key AND f.raw_ip=k.ip AND f.origin=k.origin
  AND f.observed_at>=%[2]s AND f.observed_at<%[3]s ORDER BY f.observed_at DESC LIMIT 1
 ) f`, sensor, from, until)
}

// A switch set on a partially adopted database must yield an explicit error
// even when the facts table is empty.
func checkStructuredRead(ctx context.Context, db indexedQueryer) error {
	statement := "SELECT discovery_list_assert_ready()"
	if structuredReadEnabled("address_links") {
		statement += " WHERE discovery_address_links_ready()"
	}
	rows, err := db.QueryContext(ctx, statement)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return fmt.Errorf("missing discovery list adoption state")
	}
	return rows.Err()
}
