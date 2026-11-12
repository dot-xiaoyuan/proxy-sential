package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestExpiredDirectProductStaysVisibleAsHistoryWhileAddressRefreshes(t *testing.T) {
	now := time.Now().UTC()
	modelAt := now.Add(-2 * time.Hour)
	product := Observation{
		ID: "dns-model", Origin: "dns_sd", IP: "10.161.4.10", MAC: "d4:f0:c9:04:2f:60",
		Node: "campus-204", Site: "campus-204", Domain: "enp3s0f0",
		DeviceType: "printer", ModelName: "ECOSYS M8124cidn", Confidence: "strong",
		ObservedAt: modelAt, ValidUntil: modelAt.Add(2 * time.Minute),
		Evidence: normalized.Event{Payload: map[string]any{"l2_source_mac_direct": true}},
	}
	arp := Observation{ID: "arp", Origin: "arp", IP: product.IP, MAC: product.MAC, Node: product.Node, Site: product.Site, Domain: product.Domain, ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(9 * time.Minute), Confidence: "confirmed"}
	item := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "printer", Observation: product}, {DeviceKey: "printer", Observation: arp}}, now)[0]
	if item.ClassificationStatus != "candidate" || item.DeviceType != "" || item.LastProductType != "printer" || item.LastProductAt == nil || !item.LastProductAt.Equal(modelAt) {
		t.Fatalf("historical product was lost or promoted to current: %+v", item)
	}
	other := product
	other.ID, other.DeviceType, other.ModelName, other.ObservedAt = "other", "camera", "DS-2CD2143G0-I", now.Add(-90*time.Minute)
	other.ValidUntil = other.ObservedAt.Add(2 * time.Minute)
	conflict := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "printer", Observation: product}, {DeviceKey: "printer", Observation: other}, {DeviceKey: "printer", Observation: arp}}, now)[0]
	if conflict.LastProductType != "" {
		t.Fatalf("conflicting product history was collapsed: %+v", conflict)
	}
	unattributed := product
	unattributed.Evidence.Payload = map[string]any{}
	clue := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "printer", Observation: unattributed}, {DeviceKey: "printer", Observation: arp}}, now)[0]
	if clue.LastProductType != "" {
		t.Fatalf("unattributed model became product history: %+v", clue)
	}
	rebound := arp
	rebound.MAC = "00:11:22:33:44:55"
	items := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "old", Observation: product}, {DeviceKey: "new", Observation: rebound}}, now)
	if len(items) != 2 {
		t.Fatalf("IP rebound merged different MAC identities: %+v", items)
	}
	for _, item := range items {
		if item.MAC == rebound.MAC && item.LastProductType != "" {
			t.Fatalf("historical product crossed a MAC rebound: %+v", item)
		}
	}
}
