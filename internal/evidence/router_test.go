package evidence

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestAnalyzeRoutersRequiresIndependentStrongEvidence(t *testing.T) {
	events := []normalized.Event{
		routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:01", map[string]any{"origin": "dhcp", "vendor_class": "Huawei AR1220"}),
		routerTestEvent("http", "2026-09-24T01:01:00Z", "AA:BB:CC:DD:EE:01", map[string]any{"server": "Huawei AR1220 management"}),
	}
	result, err := AnalyzeRouters(events, RouterOptions{AsOf: time.Date(2026, 9, 24, 1, 2, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 {
		t.Fatalf("expected one assessment, got %+v", result.Assessments)
	}
	got := result.Assessments[0]
	if got.Status != "confirmed" || !got.ConfirmedRouter || got.Confidence != 85 || got.IndependentSources != 2 || got.Brand != "Huawei" || got.Model != "AR1220" {
		t.Fatalf("unexpected confirmed assessment: %+v", got)
	}
}

func TestAggregateRouterEvidenceCombinesIndependentBatches(t *testing.T) {
	asOf := time.Date(2026, 9, 24, 1, 2, 0, 0, time.UTC)
	dhcp, err := AnalyzeRouters([]normalized.Event{
		routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:09", map[string]any{"vendor_class": "H3C MSR3600"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	http, err := AnalyzeRouters([]normalized.Event{
		routerTestEvent("http", "2026-09-24T01:01:00Z", "AA:BB:CC:DD:EE:09", map[string]any{"server": "H3C MSR3600 management"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append([]RouterEvidence{}, dhcp.Evidence...), http.Evidence...)
	assessment, present := AggregateRouterEvidence(combined, nil, asOf)
	if !present || assessment.Status != "confirmed" || !assessment.ConfirmedRouter || assessment.IndependentSources != 2 || assessment.Confidence != 85 {
		t.Fatalf("separate batches did not combine into a confirmed router: %+v", assessment)
	}
}

func TestAnalyzeRoutersOUINeverConfirms(t *testing.T) {
	event := routerTestEvent("device", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:02", map[string]any{"oui_vendor": "Huawei"})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 || result.Assessments[0].Status != "candidate" || result.Assessments[0].Confidence != 10 || !result.Assessments[0].BrandReferenceOnly {
		t.Fatalf("OUI-only assessment was promoted: %+v", result.Assessments)
	}
}

func TestAnalyzeRoutersExcludesInfrastructureRoles(t *testing.T) {
	for _, payload := range []map[string]any{{"software_name": "H3C WA6638"}, {"software_name": "H3C S5130 Comware"}, {"software_name": "Huawei USG6000"}, {"software_name": "H3C SecPath F1000"}, {"system_description": "Huawei Switch S12700E-8"}, {"system_description": "Huawei AC6805"}, {"system_name": "XiQu_EA5800-X7"}} {
		event := routerTestEvent("software", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:03", payload)
		result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Assessments) != 1 || result.Assessments[0].ConfirmedRouter || len(result.Assessments[0].Conflicts) == 0 {
			t.Fatalf("excluded role was not preserved: payload=%v result=%+v", payload, result.Assessments)
		}
	}
}

func TestAnalyzeRoutersAmbiguousIPAssociationCannotConfirm(t *testing.T) {
	events := []normalized.Event{
		routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "", map[string]any{"origin": "dhcp", "vendor_class": "H3C MSR3600", "vlan": "10"}),
		routerTestEvent("tls", "2026-09-24T01:01:00Z", "", map[string]any{"certificate_subject": "H3C MSR3600", "vlan": "10"}),
	}
	result, err := AnalyzeRouters(events, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range result.Assessments {
		if got.ConfirmedRouter || !got.Ambiguous {
			t.Fatalf("ambiguous IP-only association was promoted: %+v", got)
		}
	}
}

func TestAnalyzeRoutersDeduplicatesMirroredEvidence(t *testing.T) {
	first := routerTestEvent("http", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:04", map[string]any{"server": "H3C ER8300"})
	second := first
	second.Source = "zeek"
	second.EventID = "event-copy"
	result, err := AnalyzeRouters([]normalized.Event{first, second}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 || result.Assessments[0].Confidence != 30 {
		t.Fatalf("mirror changed score: %+v", result.Assessments)
	}
	foundMerged := false
	for _, item := range result.Evidence {
		if item.RuleID == "h3c-router-series" && len(item.EventIDs) == 2 {
			foundMerged = true
		}
	}
	if !foundMerged {
		t.Fatalf("mirrored event IDs were not retained: %+v", result.Evidence)
	}
}

func TestAnalyzeRoutersPreservesH3CMagicSeries(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:05", map[string]any{"vendor_class": "H3C Magic NX30 Pro"})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 || result.Assessments[0].Brand != "H3C" || result.Assessments[0].Series != "Magic" || result.Assessments[0].Model != "Magic NX30" || result.Assessments[0].Role != "router" {
		t.Fatalf("H3C Magic classification lost series or role: %+v", result.Assessments)
	}
}

func TestAnalyzeRoutersDoesNotTreatMagicDomainAsH3C(t *testing.T) {
	event := routerTestEvent("tls", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:06", map[string]any{"certificate_subject": "CN=*.magicneko.com"})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("ordinary domain was classified as H3C Magic: %+v", result)
	}
}

func TestAnalyzeRoutersDoesNotTreatOppoAx5GAsHuawei(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:07", map[string]any{"hostname": "oppo-Ax5G"})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("OPPO phone hostname was classified as a Huawei router: %+v", result)
	}
}

func TestAnalyzeRoutersPreservesHuaweiConsumerSeries(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:08", map[string]any{"vendor_class": "Huawei AX3"})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 || result.Assessments[0].Brand != "Huawei" || result.Assessments[0].Series != "AX" || result.Assessments[0].Model != "AX3" || result.Assessments[0].Role != "router" {
		t.Fatalf("Huawei AX router classification was lost: %+v", result.Assessments)
	}
}

func TestAnalyzeRoutersDoesNotTreatWindowsHostnameAsH3CGR(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:10", map[string]any{
		"hostname": "DESKTOP-GR64LPU", "vendor_class": "MSFT 5.0",
	})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("ordinary Windows hostname was classified as H3C GR: %+v", result)
	}
}

func TestAnalyzeRoutersCollapsesDHCPDerivedSoftwareSource(t *testing.T) {
	events := []normalized.Event{
		routerTestEvent("dhcp", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:11", map[string]any{"vendor_class": "Huawei WS7100"}),
		routerTestEvent("software", "2026-09-29T01:00:01Z", "AA:BB:CC:DD:EE:11", map[string]any{"software_type": "DHCP::CLIENT", "software_name": "Huawei WS7100"}),
	}
	result, err := AnalyzeRouters(events, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 {
		t.Fatalf("expected one router candidate: %+v", result)
	}
	got := result.Assessments[0]
	if got.ConfirmedRouter || got.IndependentSources != 1 || got.Confidence != 55 {
		t.Fatalf("DHCP-derived software was counted as independent evidence: %+v", got)
	}
}

func TestAnalyzeRoutersConfirmsModelWithVRRPRole(t *testing.T) {
	events := []normalized.Event{
		routerTestEvent("dhcp", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:12", map[string]any{"vendor_class": "Cisco ISR4331"}),
		routerTestEvent("vrrp", "2026-09-29T01:00:01Z", "AA:BB:CC:DD:EE:12", map[string]any{"virtual_router_id": 10, "priority": 110}),
	}
	result, err := AnalyzeRouters(events, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 {
		t.Fatalf("expected one assessment: %+v", result)
	}
	got := result.Assessments[0]
	if !got.ConfirmedRouter || got.Status != "confirmed" || got.Confidence != 95 || got.IndependentSources != 2 || got.Brand != "Cisco" {
		t.Fatalf("model plus VRRP role did not confirm router: %+v", got)
	}
}

func TestAnalyzeRoutersRecognizesMultipleVendors(t *testing.T) {
	cases := []struct {
		value string
		brand string
	}{
		{"TP-Link Archer AX73", "TP-Link"},
		{"Ruijie RG-EG210G-P", "Ruijie"},
		{"MikroTik RouterOS 7.15", "MikroTik"},
		{"Juniper MX480", "Juniper"},
		{"ZTE ZXHN H3600", "ZTE"},
		{"ASUS RT-AX86U", "ASUS"},
		{"Ubiquiti EdgeRouter", "Ubiquiti"},
		{"OpenWrt 23.05", "OpenWrt"},
	}
	for index, test := range cases {
		event := routerTestEvent("software", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:"+string(rune('A'+index)), map[string]any{"software_name": test.value})
		result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Assessments) != 1 || result.Assessments[0].Brand != test.brand || result.Assessments[0].Role != "router" {
			t.Fatalf("%q was not recognized as %s router: %+v", test.value, test.brand, result.Assessments)
		}
	}
}

func TestAnalyzeRoutersDoesNotTreatRandomRHostnameAsNetgear(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:20", map[string]any{
		"hostname": "R3RJP55G", "vendor_class": "android-dhcp-14",
	})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("random R-prefixed hostname was classified as NETGEAR: %+v", result)
	}
}

func TestAnalyzeRoutersDoesNotTreatRandomRVHostnameAsCisco(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:21", map[string]any{
		"hostname": "RV123ABC", "vendor_class": "android-dhcp-14",
	})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("random RV-prefixed hostname was classified as Cisco: %+v", result)
	}
}

func TestAnalyzeRoutersDoesNotTreatZTEPhoneAsRouter(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:22", map[string]any{
		"hostname": "ZTE A2022H", "vendor_class": "android-dhcp-14",
	})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 || result.Assessments[0].Role == "router" || result.Assessments[0].Confidence != 10 {
		t.Fatalf("ZTE phone was classified as a router: %+v", result)
	}
}

func TestAnalyzeRoutersDoesNotTreatMagicColorAsH3C(t *testing.T) {
	event := routerTestEvent("dhcp", "2026-09-29T01:00:00Z", "AA:BB:CC:DD:EE:23", map[string]any{
		"hostname": "Magic-color", "vendor_class": "udhcp",
	})
	result, err := AnalyzeRouters([]normalized.Event{event}, RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("ordinary Magic hostname was classified as H3C: %+v", result)
	}
}

func routerTestEvent(kind, timestamp, mac string, payload map[string]any) normalized.Event {
	subject := map[string]any{"ip": "192.0.2.10"}
	if mac != "" {
		subject["mac"] = mac
	}
	return normalized.Event{SchemaVersion: "v1", EventID: kind + "-event", Source: "suricata", SourceEventType: kind, Type: kind, Timestamp: timestamp, Observer: map[string]any{"sensor_id": "test"}, Subject: subject, Flow: map[string]any{"src_ip": "192.0.2.10", "dst_ip": "192.0.2.1", "proto": "tcp", "direction": "outbound"}, Payload: payload, Confidence: 1}
}
