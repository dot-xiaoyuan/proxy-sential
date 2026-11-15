package store

import (
	"context"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"time"
)

func passiveMDNSSite(e normalized.Event) string {
	if site := passiveScopeField(e, "campus_id"); site != "" {
		return site
	}
	return passiveString(e.Observer, "sensor_id")
}
func passiveMDNSDomain(e normalized.Event) string {
	if domain := passiveScopeField(e, "access_domain"); domain != "" {
		return domain
	}
	return passiveInterface(e)
}

// Canonical tuple avoids ambiguous delimiter joins; an empty VLAN remains a
// separate scope and is never treated as a wildcard for a known VLAN.
func passiveMDNSScopeKey(e normalized.Event) string {
	raw, _ := json.Marshal([]string{passiveMDNSSite(e), passiveMDNSDomain(e), passiveScopeField(e, "vlan"), passiveScopeField(e, "vrf")})
	return string(raw)
}
func inheritMDNSScope(e normalized.Event, payload map[string]any) {
	for _, key := range []string{"vlan", "vrf", "access_domain", "campus_id"} {
		if value := passiveScopeField(e, key); value != "" {
			payload[key] = value
		}
	}
	payload["source_event_id"] = e.EventID
}
func cloneMDNSPayload(p map[string]any) map[string]any {
	copy := make(map[string]any, len(p))
	for k, v := range p {
		copy[k] = v
	}
	return copy
}
func passiveMDNSAddressMAC(e normalized.Event, address string) string {
	source := passiveString(e.Flow, "src_ip")
	if source == "" {
		source = passiveString(e.Subject, "ip")
	}
	if source != address {
		return ""
	}
	return passiveDirectResponderMAC(e)
}

// The cache is reconstructible from authoritative events. Cleanup is bounded
// and relative to the earliest input, so a lagging consumer does not lose joins.
func expireMDNSScopedCache(ctx context.Context, db passiveDiscoveryDB, events []normalized.Event) error {
	var oldest time.Time
	for _, e := range events {
		if e.SourceEventType != "mdns" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err == nil && (oldest.IsZero() || at.Before(oldest)) {
			oldest = at
		}
	}
	if oldest.IsZero() {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM passive_discovery_mdns_scoped_records WHERE ctid IN (SELECT ctid FROM passive_discovery_mdns_scoped_records WHERE valid_until<$1 ORDER BY valid_until LIMIT 128 FOR UPDATE SKIP LOCKED)`, oldest.Add(-30*24*time.Hour))
	return err
}
