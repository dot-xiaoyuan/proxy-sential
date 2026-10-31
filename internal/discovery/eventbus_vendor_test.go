package discovery

import "testing"

func TestEventBusOUIRequiresDirectClientMAC(t *testing.T) {
	arp := map[string]any{"mac": "00:0c:29:aa:bb:cc", "protocols": []any{"arp"}}
	normalizeEventBusDocument(arp)
	if got, _ := arp["manufacturer"].(string); got != "" {
		t.Fatalf("routed ARP gateway MAC was treated as device vendor: %q", got)
	}
	dhcp := map[string]any{"mac": "00:0c:29:aa:bb:cc", "protocols": []any{"dhcp"}}
	normalizeEventBusDocument(dhcp)
	if got, _ := dhcp["manufacturer"].(string); got == "" {
		t.Fatal("direct DHCP client MAC lost OUI vendor clue")
	}
	asserted := map[string]any{"mac": "00:0c:29:aa:bb:cc", "protocols": []any{"arp"}, "manufacturer": "evidence vendor"}
	normalizeEventBusDocument(asserted)
	if asserted["manufacturer"] != "evidence vendor" {
		t.Fatalf("source manufacturer overwritten: %v", asserted["manufacturer"])
	}
}
