package discovery

import (
	"fmt"
	"strings"
)

// Build explicit offsets for all three encapsulations. libpcap's vlan keyword
// changes later offsets and is deliberately not used in this filter.
func DiscoveryCaptureFilter() string { return CaptureFilterFor(DefaultCollectionConfig()) }
func CaptureFilterFor(config CollectionConfig) string {
	protocol := func(ether, ip int) string {
		ports := []int{}
		for _, entry := range []struct {
			name  string
			ports []int
		}{{"dns_sd", []int{5353}}, {"ssdp", []int{1900}}, {"ws_discovery", []int{3702}}, {"snmp", []int{161, 162}}, {"dhcpv6", []int{546, 547}}, {"nbns", []int{137}}, {"llmnr", []int{5355}}, {"coap", []int{5683}}, {"bacnet", []int{47808}}} {
			if config.Enabled(entry.name) {
				ports = append(ports, entry.ports...)
			}
		}
		v4ports, v6ports := []string{}, []string{}
		for _, p := range ports {
			for _, delta := range []int{0, 2} {
				v4ports = append(v4ports, fmt.Sprintf("ether[%d+((ether[%d]&15)<<2):2]=%d", ip+delta, ip, p))
				v6ports = append(v6ports, fmt.Sprintf("ether[%d:2]=%d", ip+40+delta, p))
			}
		}
		parts := []string{}
		for _, entry := range []struct {
			name      string
			etherType int
		}{{"arp", 0x0806}, {"lldp", 0x88cc}, {"ieee1905_client_association", 0x893a}} {
			if config.Enabled(entry.name) {
				parts = append(parts, fmt.Sprintf("ether[%d:2]=%d", ether, entry.etherType))
			}
		}
		if config.Enabled("ndp") {
			parts = append(parts, fmt.Sprintf("(ether[%d:2]=0x86dd and ether[%d]=58)", ether, ip+6))
		}
		if len(ports) > 0 {
			parts = append(parts, fmt.Sprintf("(ether[%d:2]=0x0800 and ether[%d]=17 and ((ether[%d:2]&0x1fff)!=0 or (%s)))", ether, ip+9, ip+6, strings.Join(v4ports, " or ")))
			parts = append(parts, fmt.Sprintf("(ether[%d:2]=0x86dd and ((ether[%d]=17 and (%s)) or ether[%d]=0 or ether[%d]=43 or ether[%d]=44 or ether[%d]=60))", ether, ip+6, strings.Join(v6ports, " or "), ip+6, ip+6, ip+6, ip+6))
		}
		if len(parts) == 0 {
			return "ether[12:2]=0xffff"
		}
		return "(" + strings.Join(parts, " or ") + ")"
	}
	result := "(" + protocol(12, 14) + ") or ((ether[12:2]=0x8100 or ether[12:2]=0x88a8) and (" + protocol(16, 18) + " or ((ether[16:2]=0x8100 or ether[16:2]=0x88a8) and " + protocol(20, 22) + ")))"
	if config.Enabled("cdp") {
		result += " or ether dst 01:00:0c:cc:cc:cc"
	}
	return result
}
