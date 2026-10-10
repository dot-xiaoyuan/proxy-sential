//go:build !linux

package discovery

import "net"

func neighborMAC(net.IP) string { return "" }
