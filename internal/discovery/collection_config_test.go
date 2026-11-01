package discovery

import (
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"testing"
)

func TestSharedCollectionFileCannotEnableCompactPassiveKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collection.json")
	data := []byte(`{"version":1,"allowed_cidrs":"10.0.0.0/8","protocols":[],"compact_passive_event_keys":true}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadCollectionConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.CompactPassiveEventKeys {
		t.Fatal("shared collection file enabled the durable producer format")
	}
}

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
