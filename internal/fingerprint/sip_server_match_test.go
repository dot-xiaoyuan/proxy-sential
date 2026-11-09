package fingerprint

import "testing"

func TestCatalogMatchesSIPServerHeader(t *testing.T) {
	res := Default().IdentifySignals(Signals{ProtocolFields: map[string][]string{"sip_server": {"Cisco-CP-8841/9.4.1.1"}}})
	if res.DeviceType != "voip_phone" || res.Brand != "Cisco" {
		t.Fatalf("type=%q brand=%q matches=%+v", res.DeviceType, res.Brand, res.SourceMatches)
	}
}
