package discovery

import (
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCaptureDNSCompatibilityGatePreservesOldProducerShape(t *testing.T) {
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, enabled := range []bool{false, true} {
		decoder := newCaptureFrameDecoder(enabled)
		hosts := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("host.local.", 120)), source, at)
		if (!enabled && len(hosts) != 0) || (enabled && (len(hosts) != 1 || !isMDNSHostAnnouncement(hosts[0]))) {
			t.Fatalf("recordEvidenceV2=%v host output=%+v", enabled, hosts)
		}
		srv := coverageDNSSRV(120)
		srv.Body.(*dnsmessage.SRVResource).Priority = 5
		srv.Body.(*dnsmessage.SRVResource).Weight = 8
		events := decoder.Decode(coverageMDNSFrame(t, srv, coverageDNSAddress("printer.local.", 120)), source, at.Add(time.Second))
		if len(events) != 1 || str(events[0].Payload, "service_target") != "printer.local." || str(events[0].Subject, "ip") != "10.1.2.3" {
			t.Fatalf("compatibility gate lost existing service: %+v", events)
		}
		for field, want := range map[string]int{"service_priority": 5, "service_weight": 8} {
			got, exists := events[0].Payload[field]
			if enabled && got != want || !enabled && exists {
				t.Fatalf("recordEvidenceV2=%v %s=%v present=%v", enabled, field, got, exists)
			}
		}
	}
}
