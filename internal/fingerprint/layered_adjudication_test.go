package fingerprint

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestLayeredRulesContributeIndependentDimensions(t *testing.T) {
	library := MustLoad("layered", []byte("Assignment,Organization Name\n000000,Test\n"), []byte(`[
	 {"input":"ssdp_model","pattern":"Latitude","brand":"Dell","model":"Latitude","device_type":"laptop","confidence":0.95},
	 {"input":"snmp_sysdescr","pattern":"Windows","os_family":"Windows","confidence":0.9}
	]`))
	got := library.IdentifySignals(Signals{ProtocolFields: map[string][]string{"ssdp_model": {"Latitude"}, "snmp_sysdescr": {"Windows"}}})
	if got.Brand != "Dell" || got.OSFamily != "Windows" || got.OSFamilyConfidence != .9 || got.Conflict {
		t.Fatalf("independent dimensions were lost: %+v", got)
	}
}

func TestLegacyRulesCannotMatchAcrossObservationFields(t *testing.T) {
	library := MustLoad("layered", []byte("Assignment,Organization Name\n000000,Test\n"), []byte(`[{"pattern":"Alpha.*Beta","brand":"Fabricated","confidence":0.95}]`))
	got := library.IdentifySignals(Signals{Hostnames: []string{"Alpha"}, Software: []string{"Beta"}})
	if got.Brand != "" {
		t.Fatalf("cross-field phantom match: %+v", got)
	}
}

func TestCompetingModelCodesConflictOnlyTheirDimensions(t *testing.T) {
	got := Default().IdentifySignals(Signals{ProtocolFields: map[string][]string{"ssdp_model": {"ADY-AL00"}, "snmp_model": {"ALN-AL00"}}})
	if !got.Conflict || !containsDimension(got.ConflictDimensions, "model") || containsDimension(got.ConflictDimensions, "brand") || containsDimension(got.ConflictDimensions, "device_type") {
		t.Fatalf("two Huawei phones must conflict only in model: %+v", got)
	}
}

func TestWeakRulesDoNotDiscreditConfirmedDimensions(t *testing.T) {
	library := MustLoad("layered", []byte("Assignment,Organization Name\n000000,Test\n"), []byte(`[
	 {"input":"ssdp_model","pattern":"alpha","brand":"Alpha","confidence":0.95},
	 {"input":"hostname","pattern":"beta","brand":"Beta","confidence":0.6}
	]`))
	got := library.IdentifySignals(Signals{Hostnames: []string{"beta"}, ProtocolFields: map[string][]string{"ssdp_model": {"alpha"}}})
	if got.Brand != "Alpha" || got.Conflict {
		t.Fatalf("weak clue changed confirmed result: %+v", got)
	}
}

func TestCatalogDeduplicatesEquivalentValuesAndContributesOS(t *testing.T) {
	var got Result
	applySourceMatches(&got, []SourceMatch{{Brand: "Dell", OS: "Windows", Strength: "self_report"}, {Brand: "dell", OS: "windows", Strength: "self_report"}})
	if got.Conflict || got.Brand == "" || got.OSFamily == "" || got.BrandConfidence != .8 {
		t.Fatalf("same observation became conflicting votes or lost OS: %+v", got)
	}
}

func containsDimension(fields []string, value string) bool {
	for _, field := range fields {
		if field == value {
			return true
		}
	}
	return false
}

func TestFamilyRoutingKeepsIndependentConflictEvidence(t *testing.T) {
	library := MustLoad("family", []byte("Assignment,Organization Name\n000000,Test\n"), []byte(`[
 {"input":"ssdp_model","pattern":"iPhone","product_family":"iPhone","confidence":0.95},
 {"input":"snmp_sysdescr","pattern":"Windows","product_families":["iPhone"],"os_family":"Windows","confidence":0.9},
 {"input":"snmp_sysdescr","pattern":"Windows","product_families":["iPad"],"brand":"Wrong","confidence":0.9},
 {"input":"dns_sd_model","pattern":"iPad","product_family":"iPad","confidence":0.95}
 ]`))
	got := library.IdentifySignals(Signals{ProtocolFields: map[string][]string{"ssdp_model": {"iPhone14,5"}, "snmp_sysdescr": {"Windows"}, "dns_sd_model": {"iPad"}}})
	if got.OSFamily != "Windows" || got.Brand != "Apple" || !containsDimension(got.ConflictDimensions, "product_family") || containsDimension(got.ConflictDimensions, "brand") {
		t.Fatalf("family routing or independent conflict lost: %+v", got)
	}
}

func TestDimensionEvidenceReferencesOnlyContributingEvent(t *testing.T) {
	library := MustLoad("refs", []byte("Assignment,Organization Name\n000000,Test\n"), []byte(`[{"input":"ssdp_model","pattern":"alpha","brand":"Alpha","confidence":0.95}]`))
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	got := library.IdentifyEvidence("", []EvidenceSignal{
		{Protocol: "ssdp", Field: "ssdp_model", Value: "alpha", Direction: "device", Association: "mac", EventID: "hit"},
		{Protocol: "ssdp", Field: "ssdp_model", Value: "beta", Direction: "device", Association: "mac", EventID: "miss"},
		{Protocol: "ssdp", Field: "ssdp_model", Value: "alpha", Direction: "client", Association: "mac", EventID: "wrong-direction"},
	}, now)
	if len(got.DimensionEvidence) != 1 || len(got.DimensionEvidence[0].Refs) != 1 || got.DimensionEvidence[0].Refs[0].EventID != "hit" {
		t.Fatalf("evidence reference is not specific: %+v", got.DimensionEvidence)
	}
}

func TestCandidateAndEvidenceBoundsAndDuplicateConfidence(t *testing.T) {
	var got Result
	for i := 0; i < 100; i++ {
		candidate := ProductCandidate{Model: fmt.Sprint(i), Source: "test", Confidence: .9}
		addProductCandidate(&got, candidate)
		mergeDimension(&got, "brand", "Dell", .9, .85)
		recordDimensionEvidence(&got, "test", "hostname", fmt.Sprint(i), ruleValues{brand: "Dell"}, .9)
	}
	if len(got.ProductCandidates) != 16 || len(got.DimensionEvidence) != 48 || got.BrandConfidence != .9 || got.Conflict {
		t.Fatalf("bounds or duplicate confidence broken: %+v", got)
	}
}

func TestModelCodeRequiresTokenBoundaries(t *testing.T) {
	for _, text := range []string{"xADY-AL00", "ADY-AL000", "prefixSM-G991Bsuffix"} {
		if _, _, ok := lookupModelInText(text); ok {
			t.Fatalf("embedded partial model matched %q", text)
		}
	}
	for _, text := range []string{"Huawei ADY-AL00 Build/1", "(SM-G991B/DS)", "iPhone14,5"} {
		if _, _, ok := lookupModelInText(text); !ok {
			t.Fatalf("valid model variant lost %q", text)
		}
	}
}

func TestMeasuredIdentificationKeepsDeterministicResult(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	evidence := []EvidenceSignal{{Protocol: "ssdp", Field: "ssdp_model", Value: "ADY-AL00", Direction: "device", Association: "mac", EventID: "model-event"}}
	library := Default()
	want := library.IdentifyEvidence("", evidence, now)
	timings := map[string]time.Duration{}
	got := library.IdentifyEvidenceMeasured("", evidence, now, func(stage string, d time.Duration) { timings[stage] += d })
	if !reflect.DeepEqual(want, got) || len(timings) != 2 {
		t.Fatalf("timing changed result or omitted stages: timings=%v", timings)
	}
	evidence = append(evidence, EvidenceSignal{Protocol: "ssdp", Field: "ssdp_model", Value: "xADY-AL00", Direction: "device", Association: "mac", EventID: "partial-model"})
	got = library.IdentifyEvidence("", evidence, now)
	for _, e := range got.DimensionEvidence {
		for _, ref := range e.Refs {
			if ref.EventID == "partial-model" {
				t.Fatal("partial model was attached as supporting evidence")
			}
		}
	}
}

func TestStrongerDimensionReplacesUnconfirmedCandidate(t *testing.T) {
	var result Result
	mergeDimension(&result, "brand", "tentative", .8, .85)
	mergeDimension(&result, "brand", "confirmed", .95, .85)
	if result.Brand != "confirmed" || result.BrandConfidence != .95 || result.Conflict {
		t.Fatalf("stronger evidence lost: %+v", result)
	}
	mergeDimension(&result, "brand", "tentative", .8, .85)
	if result.Brand != "confirmed" || result.Conflict {
		t.Fatalf("weak evidence replaced confirmation: %+v", result)
	}
}
