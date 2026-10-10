//go:build linux

package discovery

import (
	"bufio"
	"net"
	"os"
	"strings"
)

func neighborMAC(ip net.IP) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// IP address, HW type, Flags, HW address, Mask, Device; flag 0x2 means a completed entry.
		if len(fields) >= 4 && fields[0] == ip.String() && fields[2] != "0x0" {
			if mac, err := net.ParseMAC(fields[3]); err == nil {
				return mac.String()
			}
		}
	}
	return ""
}
