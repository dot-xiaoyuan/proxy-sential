package normalized

import "testing"

func TestPacketSidecarHotPathKeepsRouterClues(t *testing.T) {
	for _, kind := range []string{"ssdp", "lldp", "dhcp", "ieee1905_topology", "ieee1905_client_association", "ieee1905_client_snapshot"} {
		event := Event{Type: "device", Source: "packet-sidecar", SourceEventType: kind}
		if !ProjectsDiscoveryHotPath(event) {
			t.Fatalf("%s must project on the packet hot path", kind)
		}
	}
	for _, kind := range []string{"ndp", "arp", "ttl", "hop_limit"} {
		event := Event{Type: "device", Source: "packet-sidecar", SourceEventType: kind}
		if ProjectsDiscoveryHotPath(event) {
			t.Fatalf("%s must stay in the packet archive and not the discovery hot path", kind)
		}
		passive := event
		passive.Source = "passive"
		if kind == "ttl" || kind == "hop_limit" {
			if ProjectsDiscoveryHotPath(passive) {
				t.Fatalf("%s is not a discovery projection event", kind)
			}
			continue
		}
		if !ProjectsDiscoveryHotPath(passive) {
			t.Fatalf("non-packet %s must keep discovery projection", kind)
		}
		legacy := event
		legacy.EventID = "stream4-legacy-0"
		if !ProjectsDiscoveryHotPath(legacy) {
			t.Fatalf("already keyed packet %s must keep its receipt", kind)
		}
	}
}

func TestKeyedSegmentKeepsStoredSubsetWhenRouterSelectionGrows(t *testing.T) {
	ndp := Event{Type: "device", Source: "packet-sidecar", SourceEventType: "ndp", EventID: "stream4-segment-0"}
	topology := Event{Type: "device", Source: "packet-sidecar", SourceEventType: "ieee1905_topology", EventID: "stream-topology"}
	events := []Event{ndp, topology}
	if !SegmentProjectsDiscovery(events, ndp) || SegmentProjectsDiscovery(events, topology) {
		t.Fatal("an existing stream4 segment changed its stored receipt subset")
	}
	fresh := []Event{{Type: "device", Source: "packet-sidecar", SourceEventType: "ieee1905_topology", EventID: "stream-topology"}}
	if !SegmentProjectsDiscovery(fresh, fresh[0]) {
		t.Fatal("a new topology segment must enter discovery projection")
	}
}
