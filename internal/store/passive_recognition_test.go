package store

import (
	"strings"
	"testing"
	"time"
)

func TestPassiveDiscoveryHintEnrichesEndpointRecognition(t *testing.T) {
	profile := EndpointIdentityProfile{
		EndpointID: "mac:0e:df:fe:48:d4:08",
		Endpoint: EndpointEntity{
			EndpointID: "mac:0e:df:fe:48:d4:08",
			PrimaryMAC: "0e:df:fe:48:d4:08",
			EntityRole: "endpoint",
			Attributes: map[string]any{"hostname": "Mac"},
		},
		DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{
			Value: "刘璐的mac mini", Origin: "dns_sd", ObservationID: "dns-sd-test", ObservedAt: time.Now().UTC(),
		}},
	}

	item := BuildEndpointDeviceInventory(profile)
	if item.Brand != "Apple" || item.Model != "Mac mini" || item.DeviceType != "desktop" || item.OSFamily != "macOS" {
		t.Fatalf("passive discovery did not enrich endpoint recognition: %+v", item)
	}
	if item.RecognitionSource != "passive_discovery" || item.RecognitionConfidence < .9 {
		t.Fatalf("passive discovery source/confidence was not retained: %+v", item)
	}
	if len(item.RecognitionEvidence) == 0 || !strings.Contains(strings.Join(item.RecognitionEvidence, " "), "DNS-SD") {
		t.Fatalf("passive discovery evidence is not traceable: %+v", item.RecognitionEvidence)
	}
}

func TestPassiveDiscoveryHintKeepsExplicitConflictVisible(t *testing.T) {
	profile := EndpointIdentityProfile{
		EndpointID: "mac:00:11:22:33:44:55",
		Endpoint: EndpointEntity{
			EndpointID: "mac:00:11:22:33:44:55",
			PrimaryMAC: "00:11:22:33:44:55",
			EntityRole: "endpoint",
			Attributes: map[string]any{"os_family": "Linux"},
		},
		DiscoveryRecognitionHints: []DiscoveryRecognitionHint{{Value: "Office Mac mini", Origin: "dns_sd"}},
	}

	item := BuildEndpointDeviceInventory(profile)
	if item.OSFamily != "Linux" || !item.RecognitionConflict {
		t.Fatalf("explicit evidence must remain authoritative and conflict visible: %+v", item)
	}
}
