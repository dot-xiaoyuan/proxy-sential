package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func TestTTLHostPathsExcludeProtocolSpecificAndNonIPv4Traffic(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		ip, dst, proto                 string
		ttl, srcPort, dstPort, version int
		want                           bool
	}{
		{"real_unicast_divergence", "10.0.0.1", "198.51.100.1", "tcp", 126, 50000, 443, 4, true},
		{"ssdp_multicast", "10.0.0.1", "239.255.255.250", "udp", 1, 1900, 1900, 4, false},
		{"mdns_multicast", "10.0.0.1", "224.0.0.251", "udp", 255, 5353, 5353, 4, false},
		{"mdns_unicast_response", "10.0.0.1", "198.51.100.1", "udp", 255, 5353, 50000, 4, false},
		{"broadcast", "10.0.0.1", "255.255.255.255", "udp", 128, 68, 67, 4, false},
		{"ipv6_hop_limit", "2001:db8::1", "2001:db8::2", "tcp", 126, 50000, 443, 6, false},
		{"ipv6_explicit_version", "10.0.0.1", "198.51.100.1", "tcp", 126, 50000, 443, 6, false},
		{"tcp_5353_is_not_mdns", "10.0.0.1", "198.51.100.1", "tcp", 126, 50000, 5353, 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := normalizedLine("base", "device", map[string]any{"origin": "ttl", "ttl": 63}, map[string]any{})
			extra := normalizedLine("extra", "device", map[string]any{"origin": "ttl", "ttl": tc.ttl, "ip_version": tc.version}, map[string]any{"dst_ip": tc.dst, "src_port": tc.srcPort, "dst_port": tc.dstPort, "proto": tc.proto})
			var e normalized.Event
			json.Unmarshal([]byte(extra), &e)
			e.Subject["ip"] = tc.ip
			var baseEvent normalized.Event
			json.Unmarshal([]byte(base), &baseEvent)
			baseEvent.Subject["ip"] = tc.ip
			baseBytes, _ := json.Marshal(baseEvent)
			base = string(baseBytes)
			extraBytes, _ := json.Marshal(e)
			result, err := Analyze(bytes.NewBufferString(base+"\n"+string(extraBytes)+"\n"), Options{})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, item := range result.Evidence {
				if item.Type == "ttl_clusters" {
					found = true
				}
			}
			if found != tc.want {
				t.Errorf("risk TTL divergence=%v want=%v", found, tc.want)
			}
			// Shared-window and generic risk aggregation must apply the same scope.
			var a normalized.Event
			json.Unmarshal([]byte(base), &a)
			now, _ := time.Parse(time.RFC3339Nano, a.Timestamp)
			windows := SharedWindows([]normalized.Event{a, e}, now.Add(-time.Minute), now, true)
			if tc.want && (len(windows) != 1 || len(windows[0].TTLPaths) != 2) {
				t.Errorf("valid shared TTL divergence lost: %+v", windows)
			}
			for _, w := range windows {
				for _, path := range w.TTLPaths {
					if !tc.want && strings.Contains(path, "observed="+fmt.Sprint(tc.ttl)) {
						t.Errorf("excluded protocol still votes in shared window: %s", path)
					}
				}
			}
		})
	}
}

func TestTTLTrafficScopeCannotReviveProtocolSpecificHostPaths(t *testing.T) {
	for _, scope := range []string{"multicast", "broadcast", "protocol_specific", "unclassified", "invalid"} {
		t.Run(scope, func(t *testing.T) {
			input := normalizedLine("base", "device", map[string]any{"ttl": 63}, map[string]any{"traffic_scope": "unicast"}) + "\n" + normalizedLine("protocol", "device", map[string]any{"ttl": 126}, map[string]any{"traffic_scope": scope}) + "\n"
			result, err := Analyze(strings.NewReader(input), Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range result.Evidence {
				if item.Type == "ttl_clusters" {
					t.Fatal("excluded normalized scope voted", scope)
				}
			}
		})
	}
}
