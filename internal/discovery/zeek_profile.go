package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type ZeekCandidate struct{ IP, VLAN, Domain, Interface, Site string }

// Use fixed Ethernet offsets instead of libpcap's stateful vlan qualifier.
func CandidateTCPFilter(candidates []ZeekCandidate) (string, error) {
	if len(candidates) > 128 {
		return "", fmt.Errorf("candidate BPF capacity exceeded: %d > 128", len(candidates))
	}
	v4, v6 := []netip.Addr{}, []netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, c := range candidates {
		ip, e := netip.ParseAddr(c.IP)
		if e != nil || !IsPrivateDiscoveryAddress(c.IP) {
			return "", fmt.Errorf("invalid candidate address")
		}
		ip = ip.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	expressions := []string{}
	for _, link := range []struct {
		ether, ip int
		prefix    string
	}{{12, 14, ""}, {16, 18, "(ether[12:2]=0x8100 or ether[12:2]=0x88a8) and "}, {20, 22, "(ether[12:2]=0x8100 or ether[12:2]=0x88a8) and (ether[16:2]=0x8100 or ether[16:2]=0x88a8) and "}} {
		addresses := []string{}
		for _, ip := range v4 {
			a := ip.As4()
			value := binary.BigEndian.Uint32(a[:])
			addresses = append(addresses, fmt.Sprintf("(ether[%d:4]=%d or ether[%d:4]=%d)", link.ip+12, value, link.ip+16, value))
		}
		if len(addresses) > 0 {
			expressions = append(expressions, fmt.Sprintf("(%sether[%d:2]=0x0800 and ether[%d]=6 and (%s))", link.prefix, link.ether, link.ip+9, strings.Join(addresses, " or ")))
		}
		addresses = []string{}
		for _, ip := range v6 {
			a := ip.As16()
			sides := []string{}
			for _, offset := range []int{8, 24} {
				parts := []string{}
				for at := 0; at < 16; at += 4 {
					parts = append(parts, fmt.Sprintf("ether[%d:4]=%d", link.ip+offset+at, binary.BigEndian.Uint32(a[at:at+4])))
				}
				sides = append(sides, "("+strings.Join(parts, " and ")+")")
			}
			addresses = append(addresses, "("+strings.Join(sides, " or ")+")")
		}
		if len(addresses) > 0 {
			expressions = append(expressions, fmt.Sprintf("(%sether[%d:2]=0x86dd and (ether[%d]=6 or ether[%d]=0 or ether[%d]=43 or ether[%d]=44 or ether[%d]=60) and (%s))", link.prefix, link.ether, link.ip+6, link.ip+6, link.ip+6, link.ip+6, link.ip+6, strings.Join(addresses, " or ")))
		}
	}
	if len(expressions) == 0 {
		return "ether[12:2]=0xffff", nil
	}
	return strings.Join(expressions, " or "), nil
}
func (r Repository) WriteZeekCandidateProfile(ctx context.Context, dir, sensor string) error {
	return r.WriteZeekCandidateProfileConfigured(ctx, dir, sensor, DefaultCollectionConfig())
}
func (r Repository) WriteZeekCandidateProfileConfigured(ctx context.Context, dir, sensor string, config CollectionConfig) error {
	rows, e := r.DB.QueryContext(ctx, `SELECT DISTINCT f.ip,f.vlan,f.domain,f.interface_name,coalesce(f.observation->>'site','') FROM discovery_service_facts_v2 f WHERE f.sensor_id=$1 AND f.valid_until>now() AND NOT f.withdrawn AND f.protocol IN ('dns_sd','ssdp','ws_discovery','dhcp','arp','ndp','bacnet','coap') ORDER BY f.ip,f.vlan,f.domain,f.interface_name LIMIT 129`, sensor)
	if e != nil {
		return e
	}
	c := []ZeekCandidate{}
	for rows.Next() {
		var v ZeekCandidate
		if e = rows.Scan(&v.IP, &v.VLAN, &v.Domain, &v.Interface, &v.Site); e != nil {
			rows.Close()
			return e
		}
		if v.IP != "" {
			c = append(c, v)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	enabled := []string{}
	for _, p := range config.Protocols {
		if p.Source == "zeek" && p.Enabled && p.Protocol != "dhcp" {
			enabled = append(enabled, p.Protocol)
		}
	}
	if len(enabled) == 0 {
		c = nil
	}
	filter, e := CandidateTCPFilter(c)
	if e != nil {
		return e
	}
	// Multiple interface/domain claims for one IP/VLAN cannot be attributed from
	// a Zeek connection alone. Omit these until a configured scope resolves them.
	counts := map[string]int{}
	for _, v := range c {
		counts[v.IP+"|"+v.VLAN]++
	}
	table := "#separator \\x09\n#set_separator ,\n#empty_field (empty)\n#unset_field -\n#fields ip\tvlan\tdomain\tinterface_name\tsite\n#types addr\tstring\tstring\tstring\tstring\n"
	for _, v := range c {
		if counts[v.IP+"|"+v.VLAN] != 1 {
			continue
		}
		fields := []string{v.IP, v.VLAN, v.Domain, v.Interface, v.Site}
		for at := range fields {
			if strings.ContainsAny(fields[at], "\t\r\n") {
				return fmt.Errorf("invalid candidate scope")
			}
			if fields[at] == "" {
				fields[at] = "(empty)"
			}
		}
		table += strings.Join(fields, "\t") + "\n"
	}
	enabledTable := "#separator \x09\n#fields protocol\n#types string\n"
	for _, p := range enabled {
		enabledTable += p + "\n"
	}
	filterTable := "#separator \\x09\n#fields id\texpression\n#types string\tstring\ncandidate\t" + filter + "\n"
	for _, file := range []struct{ name, body string }{{"zeek-candidates.tsv", table}, {"zeek-filter.tsv", filterTable}, {"zeek-enabled.tsv", enabledTable}} {
		path := filepath.Join(dir, file.name)
		prior, _ := os.ReadFile(path)
		if string(prior) == file.body {
			continue
		}
		if e = writeDurableSpool(path+".tmp", []byte(file.body)); e != nil {
			return e
		}
		if e = os.Rename(path+".tmp", path); e != nil {
			return e
		}
	}
	return nil
}
