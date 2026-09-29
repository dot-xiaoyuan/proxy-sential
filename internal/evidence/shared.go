package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
)

// SharedWindows consumes standard events only. Query completeness is explicit;
// no missing/partial observation is synthesized as a healthy negative window.
func SharedWindows(events []normalized.Event, from, to time.Time, complete bool) []sharedaccess.Window {
	type record struct {
		e                normalized.Event
		at               time.Time
		identity, digest string
	}
	records := []record{}
	for _, e := range events {
		switch e.Type {
		case "http", "tls", "quic", "device", "dns", "flow", "connection":
		default:
			continue
		}
		if isInfrastructureRole(subjectString(e, "entity_role")) {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		ip, ipErr := netip.ParseAddr(subjectString(e, "ip"))
		if err != nil || ipErr != nil || ip.IsUnspecified() || ip.IsMulticast() || e.EventID == "" {
			complete = false
			continue
		}
		if at.Before(from) || at.After(to) {
			continue
		}
		identity, _ := json.Marshal([]string{stringValue(e.Observer, "sensor_id"), e.Source, stringValue(e.Observer, "collector_instance_id"), e.EventID})
		raw, _ := json.Marshal(e)
		digest := sha256.Sum256(raw)
		records = append(records, record{e: e, at: at, identity: string(identity), digest: hex.EncodeToString(digest[:])})
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		if a.identity != b.identity {
			return a.identity < b.identity
		}
		return a.digest < b.digest
	})
	type group struct {
		w             sharedaccess.Window
		s             ipSignals
		sources, refs map[string]bool
		overflow      bool
	}
	groups := map[string]*group{}
	seen := map[string]struct{ digest, key string }{}
	for _, r := range records {
		e := r.e
		ip, _ := netip.ParseAddr(subjectString(e, "ip"))
		scope := []string{ip.Unmap().String(), stringValue(e.Observer, "sensor_id"), subjectString(e, "campus_id"), stringValue(e.Payload, "access_domain")}
		rawKey, _ := json.Marshal(scope)
		key := string(rawKey)
		g := groups[key]
		if g == nil {
			g = &group{w: sharedaccess.Window{RuleVersion: sharedaccess.RuleVersion, IP: scope[0], SensorID: scope[1], CampusID: scope[2], AccessDomain: scope[3], From: r.at, To: r.at, LastObservedAt: r.at, Complete: complete, Conflicts: []string{}}, s: newIPSignals(), sources: map[string]bool{}, refs: map[string]bool{}}
			groups[key] = g
		}
		if old, ok := seen[r.identity]; ok {
			if old.digest != r.digest {
				g.w.Conflicts = []string{"duplicate_event_changed"}
				groups[old.key].w.Conflicts = []string{"duplicate_event_changed"}
			}
			continue
		}
		seen[r.identity] = struct{ digest, key string }{r.digest, key}
		g.w.To = r.at
		g.w.LastObservedAt = r.at
		g.sources[e.Source] = true
		if issue := stringValue(e.Observer, "capture_scope_issue"); issue != "" {
			g.w.Conflicts = append(g.w.Conflicts, issue)
			g.w.Complete = false
		}
		if g.overflow {
			continue
		}
		before := len(g.s.uaOSFamilies) + len(g.s.ttlClusters) + len(g.s.tcpStacks) + len(g.s.ja3) + len(g.s.ja4) + len(g.s.deviceFamilies)
		if family := userAgentOSFamily(stringValue(e.Payload, "user_agent")); family != "" {
			g.s.uaOSFamilies[family] = struct{}{}
		}
		addString(g.s.ja3, e.Payload, "ja3")
		addString(g.s.ja4, e.Payload, "ja4")
		addString(g.s.tcpStacks, e.Payload, "tcp_stack")
		if e.Type == "device" {
			// Use protocol fields only. Hostnames, brand hints and random MACs
			// must not become an independent device signal.
			if stringValue(e.Payload, "origin") == "dhcp" {
				options := strings.TrimSpace(stringValue(e.Payload, "requested_options"))
				if options != "" {
					fingerprint := sha256.Sum256([]byte(strings.TrimSpace(stringValue(e.Payload, "vendor_class")) + "|" + options))
					g.s.deviceFamilies[hex.EncodeToString(fingerprint[:16])] = struct{}{}
				}
			}
			switch strings.ToLower(stringValue(e.Flow, "direction")) {
			case "outbound", "egress", "out", "c2s", "client_to_server", "to_server":
				if !sharedIPv4TTL(e) {
					break
				}
				flow := map[string]any{}
				for k, v := range e.Flow {
					flow[k] = v
				}
				flow["direction"] = "outbound"
				e.Flow = flow
				g.s.addTTL(e)
			}
		}
		observed := newIPSignals()
		if family := userAgentOSFamily(stringValue(e.Payload, "user_agent")); family != "" {
			observed.uaOSFamilies[family] = struct{}{}
		}
		addString(observed.ja3, e.Payload, "ja3")
		addString(observed.ja4, e.Payload, "ja4")
		addString(observed.tcpStacks, e.Payload, "tcp_stack")
		if e.Type == "device" && stringValue(e.Flow, "direction") == "outbound" && sharedIPv4TTL(e) {
			observed.addTTL(e)
		}
		if e.Type == "device" && stringValue(e.Payload, "origin") == "dhcp" {
			options := strings.TrimSpace(stringValue(e.Payload, "requested_options"))
			if options != "" {
				sum := sha256.Sum256([]byte(strings.TrimSpace(stringValue(e.Payload, "vendor_class")) + "|" + options))
				observed.deviceFamilies[hex.EncodeToString(sum[:16])] = struct{}{}
			}
		}
		for family, values := range map[string]map[string]struct{}{"ua_os": observed.uaOSFamilies, "ttl_path": observed.ttlClusters, "tcp_stack": observed.tcpStacks, "ja3": observed.ja3, "ja4": observed.ja4, "dhcp_stack": observed.deviceFamilies} {
			for value := range values {
				if !g.w.ObserveFeature(family, value, r.at) {
					g.overflow = true
					g.w.Complete = false
					g.w.Conflicts = append(g.w.Conflicts, "shared_sampling_capacity_exceeded")
				}
			}
		}
		after := len(g.s.uaOSFamilies) + len(g.s.ttlClusters) + len(g.s.tcpStacks) + len(g.s.ja3) + len(g.s.ja4) + len(g.s.deviceFamilies)
		if len(g.refs) == 0 || after != before {
			if len(g.refs) < 64 {
				g.refs[r.identity] = true
				g.w.EventIDs = append(g.w.EventIDs, e.EventID)
				g.w.Records = append(g.w.Records, sharedaccess.RecordRef{EventID: e.EventID, Source: e.Source, InstanceID: stringValue(e.Observer, "collector_instance_id")})
			}
		}
		if len(g.s.ttlClusters) > 32 || len(g.s.tcpStacks) > 32 || len(g.s.ja3) > 32 || len(g.s.ja4) > 32 || len(g.s.deviceFamilies) > 32 || len(g.sources) > 8 || len(g.refs) >= 64 {
			g.overflow = true
			g.w.Complete = false
			g.w.Conflicts = append(g.w.Conflicts, "shared_signal_cardinality_exceeded")
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []sharedaccess.Window{}
	for _, key := range keys {
		g := groups[key]
		w := g.w
		for source := range g.sources {
			w.Sources = append(w.Sources, source)
		}
		sort.Strings(w.Sources)
		w.UAOS = sortedSet(g.s.uaOSFamilies)
		w.TTLPaths = sortedSet(g.s.ttlClusters)
		w.TCPStacks = sortedSet(g.s.tcpStacks)
		w.DHCPProfiles = sortedSet(g.s.deviceFamilies)
		// JA3 and JA4 describe the same signal family and never count twice.
		if len(g.s.ja4) > 0 {
			w.TLSStacks = sortedSet(g.s.ja4)
			w.Samples["tls_stack"] = w.Samples["ja4"]
		} else {
			w.TLSStacks = sortedSet(g.s.ja3)
			if w.Samples != nil {
				w.Samples["tls_stack"] = w.Samples["ja3"]
			}
		}
		delete(w.Samples, "ja3")
		delete(w.Samples, "ja4")
		raw, _ := json.Marshal(w)
		sum := sha256.Sum256(raw)
		w.ID = "shared-" + hex.EncodeToString(sum[:16])
		out = append(out, w)
	}
	return out
}

// IPv6 Hop Limit is retained by the standard event store. It is deliberately
// excluded from the IPv4 TTL rule until a separate IPv6 rule is validated.
func sharedIPv4TTL(e normalized.Event) bool {
	ip, err := netip.ParseAddr(subjectString(e, "ip"))
	if err != nil || !ip.Is4() {
		return false
	}
	for _, fields := range []map[string]any{e.Flow, e.Payload} {
		if version, ok := numberValue(fields["ip_version"]); ok && version == 6 {
			return false
		}
	}
	return true
}
