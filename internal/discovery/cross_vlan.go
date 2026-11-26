package discovery

import "context"

// A presentation group is independent of hardware ownership. Each scoped key
// still owns its observations, address leases, history and hardware decision.
func crossVLAN(q DeviceQuery) bool {
	return q.HardwareV2 && q.structured && q.Mode == "passive" && q.IdentityScope != "address_clues" && q.IdentityScope != "scoped_devices" && structuredReadEnabled("cross_vlan")
}

const globalMACPattern = "^[0-9a-f][048c](:[0-9a-f]{2}){5}$"

// An ordered page starts with a small set of scoped keys. Expand only their
// globally administered MACs in the same site, interface and VRF, using the
// existing MAC index. The final classifier applies time, IP and conflict checks.
func vlanPeerKeys(keys string) string {
	return `ARRAY(WITH input AS MATERIALIZED (SELECT k,k::jsonb j FROM unnest(` + keys + `) k),
 macs AS (SELECT DISTINCT j->>1 sensor,j->>2 site,j->>3 domain,j->>5 vrf,j->>7 mac FROM input
 WHERE j->>0='identity' AND j->>6='mac' AND j->>7 ~ '` + globalMACPattern + `' AND j->>7<>'00:00:00:00:00:00')
 SELECT k FROM input UNION SELECT f.base_identity FROM macs m JOIN discovery_list_observation f
 ON lower(f.raw_mac)=m.mac AND (f.sensor_id,f.site_id,f.access_domain,f.vrf)=(m.sensor,m.site,m.domain,m.vrf)
 WHERE f.observed_at BETWEEN $1 AND now())`
}

// Only keys that actually share a domain and MAC need another lookup. Require
// direct, unambiguous address evidence from the selected window. No historical
// evidence documents enter this query. Hardware conflicts keep their scoped rows.
const crossVLANAssetsSQL = `, scoped_keys AS MATERIALIZED (
 SELECT identity_key,identity_key::jsonb j FROM candidate_source
), shared_macs AS (
 SELECT j-4 family FROM scoped_keys
 WHERE j->>0='identity' AND j->>6='mac' AND j->>7 ~ '` + globalMACPattern + `' AND j->>7<>'00:00:00:00:00:00'
 AND j->>1<>'' AND j->>2<>'' AND j->>3<>'' GROUP BY j-4 HAVING count(*)>1
), pair_members AS MATERIALIZED (
 SELECT k.identity_key, jsonb_build_array(m.family,coalesce(min(f.raw_ip) FILTER (WHERE strpos(f.raw_ip,':')=0),min(f.raw_ip)))::text pair_key
 FROM scoped_keys k JOIN shared_macs m ON m.family=k.j-4
 JOIN discovery_list_observation f ON f.base_identity=k.identity_key AND f.scope_valid
 AND lower(f.raw_mac)=k.j->>7 AND f.observed_at BETWEEN $1 AND now()
 AND f.origin IN ('arp','dhcp','ndp') AND f.raw_ip<>'' AND f.raw_ip NOT IN ('0.0.0.0','::')
 AND CASE WHEN pg_input_is_valid(f.raw_ip,'inet') THEN NOT (f.raw_ip::inet <<= inet 'fe80::/10') ELSE false END
 GROUP BY k.identity_key,m.family
 HAVING coalesce(min(f.raw_ip) FILTER (WHERE strpos(f.raw_ip,':')=0)=max(f.raw_ip) FILTER (WHERE strpos(f.raw_ip,':')=0),min(f.raw_ip)=max(f.raw_ip))
), compatible_pairs AS (
 SELECT p.pair_key FROM pair_members p JOIN candidate_source c USING(identity_key)
 GROUP BY p.pair_key HAVING count(*)>1 AND bool_and(c.classification_status IN ('identified','candidate'))
 AND count(DISTINCT coalesce(c.effective_types[1],nullif(c.candidate_role,'')))<=1
 AND count(DISTINCT nullif(c.verified_model,''))<=1 AND NOT bool_or(c.model_conflict)
 AND bool_and(cardinality(c.product_types)<=1)
 AND count(DISTINCT c.product_types[1])<=1
), display_members AS (
 SELECT c.*,coalesce(p.pair_key,c.identity_key) display_key
 FROM candidate_source c LEFT JOIN (SELECT p.* FROM pair_members p JOIN compatible_pairs v USING(pair_key)) p USING(identity_key)
), display_ranked AS (
 SELECT m.*,count(*) OVER family vlan_scope_count,max(last_seen) OVER family asset_last_seen,
 row_number() OVER (PARTITION BY display_key ORDER BY (classification_status='identified') DESC,
 (candidate_role<>'') DESC,(cardinality(product_types)>0) DESC,last_seen DESC,identity_key COLLATE "C") preference
 FROM display_members m WINDOW family AS (PARTITION BY display_key)
), display_assets AS (
 SELECT * FROM display_ranked WHERE preference=1
)`

// Cache only keys actually included in a ranked query. A scoped identity known
// solely through an address link can share a MAC without being a direct peer.
func unrankedVLANSeeds(ctx context.Context, db indexedQueryer, q DeviceQuery, keys []string, visited map[string]struct{}, limit int) ([]string, error) {
	pending := keys[:0]
	for _, key := range keys {
		if _, found := visited[key]; !found {
			pending = append(pending, key)
		}
	}
	if len(pending) == 0 {
		return nil, nil
	}
	covered, err := readPageKeys(ctx, db, "SELECT unnest("+vlanPeerKeys("$2::text[]")+")", q.SnapshotAt.Add(-q.Window), pending)
	if err != nil {
		return nil, err
	}
	if len(visited)+len(covered) > limit {
		clear(visited)
	}
	for _, key := range covered {
		if len(visited) >= limit {
			break
		}
		visited[key] = struct{}{}
	}
	return pending, nil
}
