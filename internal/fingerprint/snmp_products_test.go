package fingerprint

import (
	"testing"
	"time"
)

func TestReviewedSNMPSwitchDescriptionAndCounterexamples(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct{ value, kind, model string }{
		{"Ruijie Full Gigabit Security & Intelligence Access Switch (S2910-24GT4SFP-UP-H) By Ruijie Networks", "switch", "S2910-24GT4SFP-UP-H"},
		{"Ruijie Gibabit Ethernet Switch with PoE(S2900-24GT4SFP/2GT-P-L) By Ruijie Networks", "switch", "S2900-24GT4SFP/2GT-P-L"},
		{"Ruijie 10G Routing Switch(S5750-24SFP/8GT-E) By Ruijie Networks", "switch", "S5750-24SFP/8GT-E"},
		{"Ruijie AM5528-SF (802.11a/n/ac/ax and 802.11b/g/n/ax) By Ruijie Networks.", "wireless_host", "AM5528-SF"},
		{"Documentation for Ruijie Switch(S2910-24GT4SFP-UP-H) By Ruijie Networks", "", ""},
		{"Ruijie Switch() By Ruijie Networks", "", ""},
	} {
		s := hardwareSignal("snmp", "snmp_sysdescr", tc.value, "response")
		r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s}}, now)
		if r.Type != tc.kind || tc.model != "" && r.Model != tc.model {
			t.Errorf("%q: %+v", tc.value, r)
		}
	}
}
