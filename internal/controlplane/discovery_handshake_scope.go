package controlplane

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"

	"proxy-sentinel/internal/store"
)

type discoveryHandshakeScopeMap struct {
	SchemaVersion string `json:"schema_version"`
	Links         []struct {
		SensorID              string   `json:"sensor_id"`
		DiscoveryCampusID     string   `json:"discovery_campus_id"`
		DiscoveryAccessDomain string   `json:"discovery_access_domain"`
		HandshakeCampusID     string   `json:"handshake_campus_id"`
		HandshakeAccessDomain string   `json:"handshake_access_domain"`
		UserCIDRs             []string `json:"user_cidrs"`
	} `json:"links"`
}

// The discovery and handshake collectors may name the same mirror segment
// differently. Only an explicit, IP-bounded site mapping may join them.
func mappedDiscoveryHandshakeScope(path string, discoveryScope store.SharedObservationScope) (store.SharedObservationScope, bool, error) {
	if path == "" {
		return store.SharedObservationScope{}, false, nil
	}
	ip, err := netip.ParseAddr(discoveryScope.IP)
	if err != nil || ip.Is4In6() {
		return store.SharedObservationScope{}, false, errors.New("invalid discovery handshake IP")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return store.SharedObservationScope{}, false, err
	}
	var config discoveryHandshakeScopeMap
	if err := json.Unmarshal(raw, &config); err != nil {
		return store.SharedObservationScope{}, false, err
	}
	if config.SchemaVersion != "discovery-handshake-scope-map/v1" {
		return store.SharedObservationScope{}, false, errors.New("invalid discovery handshake scope map version")
	}
	var mapped store.SharedObservationScope
	matchedLinks := 0
	for _, link := range config.Links {
		if link.SensorID != discoveryScope.SensorID || link.DiscoveryCampusID != discoveryScope.CampusID || link.DiscoveryAccessDomain != discoveryScope.AccessDomain {
			continue
		}
		matchedLinks++
		if matchedLinks > 1 || link.HandshakeCampusID == "" || link.HandshakeAccessDomain == "" || len(link.UserCIDRs) == 0 {
			return store.SharedObservationScope{}, false, errors.New("ambiguous or incomplete discovery handshake scope map")
		}
		inside := false
		for _, cidr := range link.UserCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return store.SharedObservationScope{}, false, err
			}
			inside = inside || prefix.Contains(ip)
		}
		if inside {
			mapped = store.SharedObservationScope{SensorID: link.SensorID, CampusID: link.HandshakeCampusID, AccessDomain: link.HandshakeAccessDomain, IP: ip.String()}
		}
	}
	return mapped, mapped.SensorID != "", nil
}
