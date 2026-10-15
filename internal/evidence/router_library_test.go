package evidence

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

// A role-eligible library that names a router model scores like a built-in rule, and its
// name is carried on the assessment as a label.
func TestAnalyzeRoutersRecogSelfReportLabelsAndScores(t *testing.T) {
	events := []normalized.Event{
		routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:31", map[string]any{"origin": "dhcp", "vendor_class": "Huawei AR1220"}),
		routerTestEvent("http", "2026-09-24T01:01:00Z", "AA:BB:CC:DD:EE:31", map[string]any{"title": "UniFi Security Gateway"}),
	}
	result, err := AnalyzeRouters(events, RouterOptions{AsOf: time.Date(2026, 9, 24, 1, 2, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 {
		t.Fatalf("expected one assessment, got %+v", result.Assessments)
	}
	got := result.Assessments[0]
	if !hasLibrary(got.Libraries, "recog") {
		t.Fatalf("recog label missing: %v", got.Libraries)
	}
	if got.IndependentSources < 2 {
		t.Fatalf("eligible library did not count as a source: %+v", got)
	}
	if !hasComponentLibrary(got.ScoreComponents, "recog") {
		t.Fatalf("score component not tagged with library: %+v", got.ScoreComponents)
	}
}

// A copyleft library may label an existing router but must not score, name the brand,
// or add an independent source.
func TestAnalyzeRoutersCopyleftLibraryIsLabelOnly(t *testing.T) {
	asOf := time.Date(2026, 9, 24, 1, 2, 0, 0, time.UTC)
	base, err := AnalyzeRouters([]normalized.Event{
		routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:32", map[string]any{"origin": "dhcp", "vendor_class": "Huawei AR1220"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	labelled, err := AnalyzeRouters([]normalized.Event{
		routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:32", map[string]any{"origin": "dhcp", "vendor_class": "Huawei AR1220"}),
		routerTestEvent("http", "2026-09-24T01:01:00Z", "AA:BB:CC:DD:EE:32", map[string]any{"server": "Web Server"}),
	}, RouterOptions{AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Assessments) != 1 || len(labelled.Assessments) != 1 {
		t.Fatalf("assessments: base=%d labelled=%d", len(base.Assessments), len(labelled.Assessments))
	}
	a, b := base.Assessments[0], labelled.Assessments[0]
	if !hasLibrary(b.Libraries, "whatweb") {
		t.Fatalf("copyleft label missing: %v", b.Libraries)
	}
	if b.Confidence != a.Confidence || b.IndependentSources != a.IndependentSources || b.Status != a.Status || b.Brand != a.Brand || b.Model != a.Model {
		t.Fatalf("copyleft label changed scoring: base=%+v labelled=%+v", a, b)
	}
}

// Labels never create a router: a copyleft match alone is not an assessment.
func TestAnalyzeRoutersLabelAloneCreatesNoAssessment(t *testing.T) {
	result, err := AnalyzeRouters([]normalized.Event{
		routerTestEvent("http", "2026-09-24T01:01:00Z", "AA:BB:CC:DD:EE:33", map[string]any{"server": "Web Server"}),
	}, RouterOptions{AsOf: time.Date(2026, 9, 24, 1, 2, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 0 {
		t.Fatalf("label-only match created an assessment: %+v", result.Assessments)
	}
}

func hasLibrary(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func hasComponentLibrary(list []RouterScoreComponent, want string) bool {
	for _, item := range list {
		if item.Library == want {
			return true
		}
	}
	return false
}

var _ = normalized.Event{}

// SNMP system descriptions reach the catalog as snmp_sysdescr, so a library rule can label
// a management platform; the label alone does not create a router.
func TestRouterInputsCarryOnlySNMPSystemDescriptionFromSNMP(t *testing.T) {
	snmp := routerTestEvent("snmp", "2026-09-24T01:01:00Z", "AA:BB:CC:DD:EE:34", map[string]any{"origin": "snmp", "system_description": "UniFi Security Gateway"})
	snmp.SourceEventType = "snmp"
	if got := routerInputs(snmp)["snmp_sysdescr"]; len(got) != 1 || got[0] != "UniFi Security Gateway" {
		t.Fatalf("snmp description not carried: %v", got)
	}
	lldp := routerTestEvent("lldp", "2026-09-24T01:01:00Z", "AA:BB:CC:DD:EE:35", map[string]any{"system_description": "Cisco IOS"})
	lldp.SourceEventType = "lldp"
	if got := routerInputs(lldp)["snmp_sysdescr"]; len(got) != 0 {
		t.Fatalf("lldp description leaked into SNMP input: %v", got)
	}
}

// A DHCP vendor class that a role-eligible library names as an access point scores as a
// router-role basis and is labelled with its library. This is the path Zeek option data
// enables on the sensor; without requested_options/vendor_class on the DHCP log it cannot fire.
func TestAnalyzeRoutersDHCPLibraryAccessPointScoresWithLabel(t *testing.T) {
	events := []normalized.Event{
		routerTestEvent("dhcp", "2026-09-24T01:00:00Z", "AA:BB:CC:DD:EE:36", map[string]any{"origin": "dhcp", "vendor_class": "Cisco AP c1140"}),
	}
	result, err := AnalyzeRouters(events, RouterOptions{AsOf: time.Date(2026, 9, 24, 1, 2, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assessments) != 1 {
		t.Fatalf("expected one access-point assessment, got %+v", result.Assessments)
	}
	got := result.Assessments[0]
	if !hasLibrary(got.Libraries, "recog") || got.Role != "ap" {
		t.Fatalf("recog access-point label/role missing: role=%s libs=%v", got.Role, got.Libraries)
	}
}
