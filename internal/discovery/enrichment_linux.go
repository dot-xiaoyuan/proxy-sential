//go:build linux

package discovery

import (
	"net"
	"os"
	"strings"
)

func verifyEnrichmentPath(o Observation, p EnrichmentPath) bool {
	if o.MAC == "" {
		return false
	}
	iface, e := net.InterfaceByName(p.Interface)
	if e != nil || iface.Flags&net.FlagUp == 0 {
		return false
	}
	ip := net.ParseIP(o.IP)
	if ip == nil {
		return false
	}
	local := false
	addresses, _ := iface.Addrs()
	for _, a := range addresses {
		if n, ok := a.(*net.IPNet); ok && n.Contains(ip) && !n.IP.Equal(ip) {
			local = true
		}
	}
	if !local {
		return false
	}
	raw, e := os.ReadFile("/proc/net/arp")
	if e != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		v := strings.Fields(line)
		if len(v) == 6 && v[0] == o.IP && v[2] == "0x2" && strings.EqualFold(v[3], o.MAC) && v[5] == p.Interface {
			return true
		}
	}
	return false
}
