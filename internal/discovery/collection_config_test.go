package discovery

import (
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"testing"
)

func TestSharedCollectionFileCannotEnableCompactPassiveKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collection.json")
	data := []byte(`{"version":1,"allowed_cidrs":"10.0.0.0/8","protocols":[],"compact_passive_event_keys":true,"stream3_passive_event_keys":true}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadCollectionConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.CompactPassiveEventKeys || config.Stream3PassiveEventKeys {
		t.Fatal("shared collection file enabled the durable producer format")
	}
}

func TestPassiveStream3KeyModeDefaultsOffAndOverridesStream2OnlyWhenSelected(t *testing.T) {
	config := DefaultCollectionConfig()
	if config.Stream3PassiveEventKeys || passiveStreamKeyScheme(config) != passiveEventKeyLegacy {
		t.Fatal("stream3 producer default changed")
	}
	config.CompactPassiveEventKeys = true
	if passiveStreamKeyScheme(config) != passiveEventKeyStream2 {
		t.Fatal("existing stream2 producer was not selected")
	}
	config.Stream3PassiveEventKeys = true
	if passiveStreamKeyScheme(config) != passiveEventKeyStream3 {
		t.Fatal("explicit stream3 producer was not selected")
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
