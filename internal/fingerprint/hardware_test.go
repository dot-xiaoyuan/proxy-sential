package fingerprint

import (
	"strings"
	"testing"
	"time"
)

func hardwareSignal(protocol, field, value, id string) EvidenceSignal {
	return EvidenceSignal{Protocol: protocol, Field: field, Value: value, EventID: id, Association: "direct", Direction: "device", ObservedAt: time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)}
}

func TestHardwareTrustedSADPAndConflict(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	s := hardwareSignal("sadp", "sadp_model", "DS-K1T6QT-F72M", "sadp1")
	s.ValidUntil = now.Add(-time.Hour) // product identity is independent of service TTL
	r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s}}, now)
	if r.Type != "access_control" || r.Model != "DS-K1T6QT-F72M" || r.TypeStatus != "identified" || len(r.Sources) == 0 {
		t.Fatalf("SADP: %+v", r)
	}
	if r = EvaluateHardware(HardwareInput{Evidence: []EvidenceSignal{s}}, now); r.Type != "" {
		t.Fatalf("untrusted identity promoted: %+v", r)
	}
	s.Direction = "destination"
	if r = EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s}}, now); r.Type != "" {
		t.Fatalf("wrong direction promoted: %+v", r)
	}
	s.Direction = "device"
	c := hardwareSignal("sadp", "sadp_model", "DS-2CD2143G2-I", "sadp2")
	r = EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s, c, s}}, now)
	if r.Type != "" || r.TypeStatus != "conflict" || len(r.ConflictingTypes) != 2 {
		t.Fatalf("conflict: %+v", r)
	}
}

func TestHardwareSNMPConditionsStayWithinResponse(t *testing.T) {
	rule := HardwareSNMPRule{ID: "fixture", Source: "librenms", Version: "fixture", Type: "environment_monitor", Condition: HardwareCondition{All: []HardwareCondition{
		{Field: "snmp_sysoid", Operator: "oid_prefix", Value: "1.3.6.1.4.1.999"},
		{Field: "oid:1.3.6.1.4.1.999.2.0", Operator: "contains", Value: "sensor"},
		{Not: &HardwareCondition{Field: "snmp_sysdescr", Operator: "contains", Value: "simulator"}},
	}}}
	e, err := ParseHardwareCatalog([]byte(`{"version":"fixture","converter_version":"fixture","sources":[],"recog_files":{},"models":[],"snmp":[]}`), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	e.snmp = []HardwareSNMPRule{rule}
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	a := hardwareSignal("snmp", "snmp_sysoid", "1.3.6.1.4.1.999.1", "a")
	b := hardwareSignal("snmp", "snmp_oid_values", `{"1.3.6.1.4.1.999.2.0":"sensor"}`, "b")
	c := hardwareSignal("snmp", "snmp_sysdescr", "real unit", "a")
	if r := e.Evaluate(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{a, b, c}}, now); r.Type != "" {
		t.Fatalf("cross-response AND: %+v", r)
	}
	b.EventID = "a"
	if r := e.Evaluate(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{a, b}}, now); r.Type != "" {
		t.Fatalf("missing exclusion input widened: %+v", r)
	}
	if r := e.Evaluate(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{a, b, c}}, now); r.Type != "environment_monitor" {
		t.Fatalf("complete AND: %+v", r)
	}
	c.Value = "simulator"
	if r := e.Evaluate(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{a, b, c}}, now); r.Type != "" {
		t.Fatalf("exclusion ignored: %+v", r)
	}
}

func TestNativeRecogCapturesAndBroadHikvision(t *testing.T) {
	e, err := ParseHardwareCatalog([]byte(`{"version":"fixture","converter_version":"fixture","sources":[],"recog_files":{"recog/xml/snmp_sysdescr.xml":"snmp_sysdescr"},"models":[],"snmp":[]}`), []byte(`{"recog/xml/snmp_sysdescr.xml":"<fingerprints matches=\"snmp.sysdescr\"><fingerprint pattern=\"^Unit ([A-Z0-9]+)$\"><example hw.product=\"X2\">Unit X2</example><param pos=\"0\" name=\"hw.device\" value=\"Printer\"/><param pos=\"1\" name=\"hw.product\"/></fingerprint></fingerprints>"}`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	r := e.Evaluate(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("snmp", "snmp_sysdescr", "Unit X2", "a")}}, now)
	if r.Type != "printer" || r.Model != "X2" {
		t.Fatalf("native captures: %+v", r)
	}
	s := hardwareSignal("http_device", "http_server", "Hikvision-Webs", "h")
	s.Direction = "server"
	r = EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s}}, now)
	if r.Type != "" {
		t.Fatalf("generic Hikvision must remain clue: %+v", r)
	}
}

func TestHardwareCanonicalTypes(t *testing.T) {
	for from, to := range map[string]string{"nvr": "recorder", "DVR": "recorder", "environment": "environment_monitor", "ups": "ups", "pdu": "pdu"} {
		if got := CanonicalHardwareType(from); got != to {
			t.Errorf("%s=%s want %s", from, got, to)
		}
	}
}

func TestHardwareInputLimitNeverSilentlyDropsConflict(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	s := hardwareSignal("sadp", "sadp_model", "DS-K1T6QT-F72M", "s")
	items := make([]EvidenceSignal, 129)
	for i := range items {
		items[i] = s
	}
	items[128] = hardwareSignal("sadp", "sadp_model", "DS-2CD2143G2-I", "z")
	r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: items}, now)
	if !r.Incomplete || r.Error == "" || r.Type != "" {
		t.Fatalf("silently truncated: %+v", r)
	}
	s.Value = string(make([]byte, 513))
	r = EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s}}, now)
	if !r.Incomplete || r.Type != "" {
		t.Fatalf("oversized model accepted: %+v", r)
	}
}

func TestHardwareLibreNMSExtractionAndOpenWrt(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	input := HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{
		hardwareSignal("snmp", "snmp_sysoid", "1.3.6.1.4.1.25506.1.112", "s"),
		hardwareSignal("snmp", "snmp_sysdescr", "H3C Comware Platform Software, Version 5.20, Release 2220\nH3C S5500-28C-EI\r\n", "s"),
	}}
	r := EvaluateHardware(input, now)
	if r.Model != "S5500-28C-EI" {
		t.Fatalf("Comware extraction: %+v", r)
	}
	input.Evidence = []EvidenceSignal{hardwareSignal("snmp", "snmp_sysoid", "1.3.6.1.4.1.52674.500", "n"), hardwareSignal("snmp", "snmp_oid_values", `{"1.3.6.1.4.1.318.1.4.2.2.1.2.1":"NetBotz 750"}`, "n")}
	r = EvaluateHardware(input, now)
	if r.Type != "environment_monitor" || r.Model != "NetBotz 750" {
		t.Fatalf("NetBotz: %+v", r)
	}
	input.Evidence = []EvidenceSignal{hardwareSignal("dns_sd", "dns_sd_model", "TP-Link Archer C7", "o")}
	r = EvaluateHardware(input, now)
	if r.Type != "router" || r.Model != "Archer C7" {
		t.Fatalf("reviewed OpenWrt: %+v", r)
	}
}

func TestHardwareReviewedMultifunctionModels(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	for _, model := range []string{"Canon MF260 Series", "ECOSYS M8124cidn"} {
		r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("dns_sd", "dns_sd_model", model, "dns")}}, now)
		if r.Type != "printer" || len(r.Capabilities) != 1 || r.Capabilities[0] != "scanning" {
			t.Fatalf("multifunction model %s: %+v", model, r)
		}
	}
}

func TestHardwareReviewedSiteModelsV2(t *testing.T) {
	now := time.Date(2026, 11, 12, 4, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ protocol, field, model, kind string }{
		{"dns_sd", "dns_sd_model", "HP LaserJet MFP M227-M231", "printer"},
		{"sadp", "sadp_model", "DS-7808N-Q2", "recorder"},
	} {
		r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal(tc.protocol, tc.field, tc.model, "retained-observation")}}, now)
		if r.Type != tc.kind || r.Model != tc.model || r.Version != "hardware-catalog-2026-11-12.2" {
			t.Fatalf("reviewed model %s: %+v", tc.model, r)
		}
		if tc.kind == "printer" && (strings.Contains(strings.ToLower(r.Model), "fdn") || len(r.Capabilities) != 1 || r.Capabilities[0] != "scanning") {
			t.Fatalf("series over-inferred: %+v", r)
		}
	}
	for _, model := range []string{"E528C-PWR", "S5570S-28S-HPWR-EI-A"} {
		descr := "H3C Comware Platform Software, Software Version 7.1.070, Release 6126P20\r\nH3C " + model + "\r\nCopyright (c) H3C"
		in := HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("snmp", "snmp_sysoid", "1.3.6.1.4.1.25506.1.112", "s"), hardwareSignal("snmp", "snmp_sysdescr", descr, "s")}}
		r := EvaluateHardware(in, now)
		if r.Type != "switch" || r.Model != model {
			t.Fatalf("SNMP extraction to reviewed switch: %+v", r)
		}
		libre, reviewed := false, false
		for _, source := range r.Sources {
			libre = libre || source.Source == "librenms" && source.Fields["hw.product"] == model
			reviewed = reviewed || source.Source == "verified_model" && source.RuleVersion == "hardware-model-review-2026-11-12.2"
		}
		if !libre || !reviewed {
			t.Fatalf("missing extraction/rule provenance: %+v", r)
		}
		in.IdentityTrusted = false
		if r := EvaluateHardware(in, now); r.Type != "" {
			t.Fatalf("unattributed historical response promoted: %+v", r)
		}
	}
	for _, model := range []string{"HP LaserJet", "HP LaserJet MFP M227-M231 firmware", "DS-7808N-Q20", "DS-7808N-Q2/8P", "H3C", "E528C-PWR-OTHER", "S5570S-28S-HPWR-EI"} {
		r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("dns_sd", "dns_sd_model", model, "negative")}}, now)
		if r.Type != "" {
			t.Fatalf("unreviewed near-match %s: %+v", model, r)
		}
	}
	for _, descr := range []string{"H3C Comware", "H3C Comware Platform Software, Software Version 7.1.070, Release 6126P20\r\nH3C UNREVIEWED-MODEL\r\nCopyright (c) H3C"} {
		r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("snmp", "snmp_sysoid", "1.3.6.1.4.1.25506", "family"), hardwareSignal("snmp", "snmp_sysdescr", descr, "family")}}, now)
		if r.Type != "" {
			t.Fatalf("H3C enterprise/unknown model assigned switch: %+v", r)
		}
	}
}

func TestHardwareInstalledV7CannotUseEmbeddedRules(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	l := mustLoadEmbedded()
	l.version = "installed-v7"
	l.installedBundleSchema = BundleSchemaVersionV7
	input := HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("sadp", "sadp_model", "DS-K1T6QT-F72M", "s")}}
	for _, in := range []HardwareInput{{}, input} {
		r := l.EvaluateHardware(in, now)
		if !r.Incomplete || r.Error == "" || r.Type != "" || r.Version != "" || r.SourceStatus != "unavailable" || r.BundleVersion != "installed-v7" || r.BundleSchema != BundleSchemaVersionV7 {
			t.Fatalf("installed V7 silently used embedded hardware: %+v", r)
		}
	}
	l.installedBundleSchema = ""
	r := l.EvaluateHardware(input, now)
	if r.SourceStatus != "embedded_replay" || r.BundleVersion != "" || r.BundleSchema != "" || r.Version == "" || r.Type != "access_control" {
		t.Fatalf("local replay source mislabeled: %+v", r)
	}
}

func TestHardwareH3CLineBreaksPreserveNativeAndLibreNMSInputs(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name, description, model string
		native                   bool
	}{
		{"recog-upstream", "H3C Comware Platform Software, Software Version 5.20 Release 2208\r\nH3C S5500-28C-EI\r\nCopyright (c) 2004-2010 Hangzhou H3C Tech. Co., Ltd. All rights reserved.", "S5500-28C-EI", true},
		{"site-description-format", "H3C Comware Platform Software, Software Version 7.1.070, Release 6126P20\r\nH3C E528C-PWR\r\nCopyright (c) 2004-2018 New H3C Technologies Co., Ltd. All rights reserved.", "E528C-PWR", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("snmp", "snmp_sysdescr", tc.description, "s"), hardwareSignal("snmp", "snmp_sysoid", "1.3.6.1.4.1.25506.1.112", "s")}}
			r := defaultHardwareCatalog().Evaluate(in, now)
			if r.Model != tc.model {
				t.Fatalf("multiline model lost: %+v", r)
			}
			native, libre := false, false
			for _, s := range r.Sources {
				native = native || s.Source == "recog" && s.Fields["hw.product"] == tc.model
				libre = libre || s.Source == "librenms" && s.Fields["hw.product"] == tc.model
			}
			if native != tc.native || !libre {
				t.Fatalf("source semantics native=%t libre=%t: %+v", native, libre, r)
			}
			in.Evidence[0].Value = strings.NewReplacer("\r", `\x0d`, "\n", `\x0a`).Replace(tc.description)
			r = defaultHardwareCatalog().Evaluate(in, now)
			if r.Model != "" {
				t.Fatalf("matcher must not reinterpret literal escaped text: %+v", r)
			}
		})
	}
}

func BenchmarkHardwareSNMP(b *testing.B) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	in := HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{hardwareSignal("snmp", "snmp_sysoid", "1.3.6.1.4.1.52674.500", "n"), hardwareSignal("snmp", "snmp_oid_values", `{"1.3.6.1.4.1.318.1.4.2.2.1.2.1":"NetBotz 750"}`, "n")}}
	h := defaultHardwareCatalog()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Evaluate(in, now)
	}
}
