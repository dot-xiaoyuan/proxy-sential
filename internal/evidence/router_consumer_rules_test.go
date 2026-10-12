package evidence

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

// Strings below follow values observed on the 184 campus mirror (2026-10-12);
// MACs and suffix digits are synthetic.
func consumerRouterEvent(kind, timestamp, mac string, payload map[string]any) normalized.Event {
	event := routerTestEvent(kind, timestamp, mac, payload)
	event.EventID = kind + "-" + mac + "-" + timestamp
	return event
}

func TestTPLinkSelfReportedModelBecomesLikelyFromDHCPAlone(t *testing.T) {
	asOf := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)
	result, err := AnalyzeRouters([]normalized.Event{
		consumerRouterEvent("dhcp", "2026-10-12T02:59:00Z", "AA:BB:CC:00:00:01", map[string]any{"hostname": "TL-WDR7666千兆易展版", "vendor_class": "MSFT 5.0"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 {
		t.Fatalf("assessments: %+v", result.Assessments)
	}
	got := result.Assessments[0]
	// One self-report is strong but still a single source: it must not be confirmed.
	if got.Status != "likely" || got.ConfirmedRouter || got.Role != "router" || got.Brand != "TP-Link" || got.Model != "TL-WDR7666" {
		t.Fatalf("DHCP hostname router model: %+v", got)
	}
}

func TestDHCPAndSSDPSelfReportsConfirmTPLinkRouter(t *testing.T) {
	asOf := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)
	result, err := AnalyzeRouters([]normalized.Event{
		consumerRouterEvent("dhcp", "2026-10-12T02:58:00Z", "AA:BB:CC:00:00:02", map[string]any{"hostname": "TL-WDR5620千兆易展版", "vendor_class": "MSFT 5.0"}),
		consumerRouterEvent("ssdp", "2026-10-12T02:59:00Z", "AA:BB:CC:00:00:02", map[string]any{"server": "TPOS/1.0.0 UPnP/1.0 TL-WDR5620千兆易展版/9.0", "nt": "urn:schemas-upnp-org:service:WANIPConnection:1"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 {
		t.Fatalf("assessments: %+v", result.Assessments)
	}
	got := result.Assessments[0]
	if got.Status != "confirmed" || !got.ConfirmedRouter || got.IndependentSources != 2 || got.Model != "TL-WDR5620" {
		t.Fatalf("independent DHCP and SSDP self-reports did not confirm: %+v", got)
	}
}

func TestSSDPServerModelAloneStaysCandidateAndGenericStackStaysWeak(t *testing.T) {
	asOf := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)
	result, err := AnalyzeRouters([]normalized.Event{
		consumerRouterEvent("ssdp", "2026-10-12T02:59:00Z", "AA:BB:CC:00:00:03", map[string]any{"server": "vxWorks/5.5 UPnP/1.0 TL-XDR3010易展版/7.0"}),
		consumerRouterEvent("ssdp", "2026-10-12T02:59:00Z", "AA:BB:CC:00:00:04", map[string]any{"server": "Linux/3.0.8, UPnP/1.0, Portable SDK for UPnP devices/1.6.19", "nt": "urn:schemas-upnp-org:device:MediaRenderer:1"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]RouterAssessment{}
	for _, item := range result.Assessments {
		byMAC[item.MAC] = item
	}
	if got := byMAC["aa:bb:cc:00:00:03"]; got.Model != "TL-XDR3010" || got.Confidence != 55 || got.Status != "candidate" {
		t.Fatalf("SSDP model self-report: %+v", got)
	}
	if got, ok := byMAC["aa:bb:cc:00:00:04"]; ok && got.Role == "router" {
		t.Fatalf("generic UPnP media stack became a router: %+v", got)
	}
}

func TestTPLinkSwitchAndAPModelsAreExcludedFromRouterRole(t *testing.T) {
	asOf := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)
	result, err := AnalyzeRouters([]normalized.Event{
		consumerRouterEvent("dhcp", "2026-10-12T02:59:00Z", "AA:BB:CC:00:00:05", map[string]any{"vendor_class": "TL-SG5428"}),
		consumerRouterEvent("dhcp", "2026-10-12T02:59:00Z", "AA:BB:CC:00:00:06", map[string]any{"hostname": "MiWiFi-RD03"}),
		consumerRouterEvent("dhcp", "2026-10-12T02:59:00Z", "AA:BB:CC:00:00:07", map[string]any{"hostname": "vivo-S19", "vendor_class": "android-dhcp-15"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]RouterAssessment{}
	for _, item := range result.Assessments {
		byMAC[item.MAC] = item
	}
	if got := byMAC["aa:bb:cc:00:00:05"]; got.ConfirmedRouter || got.Status == "likely" || got.Role == "router" {
		t.Fatalf("TP-Link switch treated as router: %+v", got)
	}
	if got := byMAC["aa:bb:cc:00:00:06"]; got.Brand != "Xiaomi" || got.Model != "RD03" || got.Status != "likely" {
		t.Fatalf("Xiaomi MiWiFi hostname: %+v", got)
	}
	if got, ok := byMAC["aa:bb:cc:00:00:07"]; ok && (got.Role == "router" || got.Status != "candidate") {
		t.Fatalf("phone hostname produced router evidence: %+v", got)
	}
}
