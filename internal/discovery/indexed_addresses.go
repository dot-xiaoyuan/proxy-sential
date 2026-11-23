package discovery

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// The latest-observation relation keeps one row per device/source/protocol
// partition after expiry. Only address facts for keys on this page are read.
// A still-valid peer claiming the same IP or a newer DHCP withdrawal blocks
// current use in that scope while preserving the positive observation.
const scopedDiscoveryAddressQuery = `SELECT b.data, b.valid_until>$2 AND NOT EXISTS (
 SELECT 1 FROM discovery_observation_latest p
 WHERE coalesce(p.data->>'ip','')<>'' AND p.data->>'ip'=b.data->>'ip'
   AND p.origin IN ('arp','ndp','dhcp') AND p.observed_at<=$2
   AND p.data->>'node'=b.data->>'node' AND p.data->>'site'=b.data->>'site' AND p.data->>'domain'=b.data->>'domain'
   AND coalesce(p.data->>'vlan','')=coalesce(b.data->>'vlan','') AND coalesce(p.data->>'vrf','')=coalesce(b.data->>'vrf','')
   AND coalesce(p.data->'evidence'->'observer'->>'capture_scope_issue','')=''
   AND coalesce(p.data->'evidence'->'payload'->>'endpoint_identity_unverified','')<>'true'
   AND ((NOT p.withdrawn AND p.valid_until>$2 AND p.data->>'confidence'='confirmed'
         AND coalesce(p.data->>'mac','')<>'' AND lower(p.data->>'mac')<>lower(b.data->>'mac'))
     OR (p.withdrawn AND p.origin='dhcp' AND p.observed_at>=b.observed_at AND lower(p.data->>'mac')=lower(b.data->>'mac')))
)
FROM discovery_observation_latest b
WHERE b.device_key=ANY($1::text[]) AND b.origin IN ('arp','ndp','dhcp') AND coalesce(b.data->>'ip','')<>''
  AND NOT b.withdrawn AND b.observed_at<=$2 AND b.data->>'confidence'='confirmed'
ORDER BY b.observed_at DESC,b.id DESC`

func attachScopedDiscoveryAddresses(ctx context.Context, db indexedQueryer, items []DeviceView, at time.Time) error {
	positions := make(map[string]int, len(items))
	keys := make([]string, 0, len(items))
	for i := range items {
		item := &items[i]
		current := []string{}
		item.CurrentAddresses = &current
		for _, observation := range item.Observations {
			if scopedAddressIdentity(observation) == item.indexedIdentityKey {
				positions[item.indexedIdentityKey] = i
				keys = append(keys, observation.Key())
				break
			}
		}
	}
	if len(keys) == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, scopedDiscoveryAddressQuery, keys, at)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var current bool
		if err := rows.Scan(&raw, &current); err != nil {
			return err
		}
		var observation Observation
		if err := json.Unmarshal(raw, &observation); err != nil {
			return err
		}
		index, ok := positions[scopedAddressIdentity(observation)]
		if !ok || !observation.ValidUntil.After(observation.ObservedAt) || !hardwareDirectOwnership(observation) {
			continue
		}
		ip, err := netip.ParseAddr(observation.IP)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		item := &items[index]
		if item.LastObservedIP == "" {
			item.LastObservedIP = ip.String()
			item.LastObservedIPAt = &observation.ObservedAt
		}
		if current {
			*item.CurrentAddresses = append(*item.CurrentAddresses, ip.String())
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range items {
		addresses := *items[i].CurrentAddresses
		sort.Slice(addresses, func(i, j int) bool {
			leftV6, rightV6 := strings.Contains(addresses[i], ":"), strings.Contains(addresses[j], ":")
			if leftV6 != rightV6 {
				return !leftV6
			}
			return addresses[i] < addresses[j]
		})
		*items[i].CurrentAddresses = slices.Compact(addresses)
	}
	return nil
}

func scopedAddressIdentity(o Observation) string {
	mac := canonicalEndpointMAC("mac:" + strings.ToLower(o.MAC))
	if mac == "" || o.Node == "" || o.Site == "" || o.Domain == "" {
		return ""
	}
	return HardwareIdentityKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF, mac)
}
