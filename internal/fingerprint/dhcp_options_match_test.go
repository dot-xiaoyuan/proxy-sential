package fingerprint

import "testing"

func TestCatalogMatchesDHCPOptions(t *testing.T) {
	res := Default().IdentifySignals(Signals{ProtocolFields: map[string][]string{"dhcp_options": {"53,57,55,60,61"}, "dhcp_message_type": {"discover"}}})
	for _, m := range res.SourceMatches {
		if m.Name == "3Com IP Phone" {
			if m.Strength != "auxiliary" {
				t.Fatalf("strength=%s", m.Strength)
			}
			return
		}
	}
	t.Fatalf("no dhcp_options match: %+v", res.SourceMatches)
}
