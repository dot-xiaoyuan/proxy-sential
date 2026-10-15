package discovery

import (
	"proxy-sentinel/internal/normalized"
	"testing"
)

func TestIngestOwnsOnlyConfiguredZeekProtocols(t *testing.T) {
	c := DefaultCollectionConfig()
	for _, tc := range []struct {
		source, protocol string
		allowed          bool
	}{
		{"zeek", "dhcp", true}, {"device-signals", "arp", false},
		{"passive", "ssdp", false}, {"zeek", "ssdp", false},
		{"zeek", "mqtt", false}, {"device-signals", "dhcp", false},
	} {
		if got := c.IngestOwns(normalized.Event{Source: tc.source, SourceEventType: tc.protocol}); got != tc.allowed {
			t.Fatalf("source=%s protocol=%s admitted=%v", tc.source, tc.protocol, got)
		}
	}
}
