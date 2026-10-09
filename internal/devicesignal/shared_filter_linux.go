//go:build linux

package devicesignal

import "syscall"

// sharedSignalSocketFilter accepts only initial TCP SYN packets (without ACK)
// for untagged or single-tagged IPv4/IPv6 Ethernet frames. The accept return
// value is deliberately capped at 128 bytes: Ethernet, IP, TCP and TCP options
// reach userspace, while application payload does not.
//
// Generated from this libpcap expression and then capped to 128 bytes:
//
//	((ip and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or
//	 (ip6 and ip6[6] == 6 and ip6[53] & 0x12 == 0x02)) or
//	(vlan and ((ip and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or
//	 (ip6 and ip6[6] == 6 and ip6[53] & 0x12 == 0x02)))
var sharedSignalSocketFilter = []syscall.SockFilter{
	{Code: 40, Jt: 0, Jf: 0, K: 12},
	{Code: 21, Jt: 0, Jf: 8, K: 2048},
	{Code: 48, Jt: 0, Jf: 0, K: 23},
	{Code: 21, Jt: 0, Jf: 32, K: 6},
	{Code: 40, Jt: 0, Jf: 0, K: 20},
	{Code: 69, Jt: 30, Jf: 0, K: 8191},
	{Code: 177, Jt: 0, Jf: 0, K: 14},
	{Code: 80, Jt: 0, Jf: 0, K: 27},
	{Code: 84, Jt: 0, Jf: 0, K: 18},
	{Code: 21, Jt: 25, Jf: 26, K: 2},
	{Code: 21, Jt: 0, Jf: 5, K: 34525},
	{Code: 48, Jt: 0, Jf: 0, K: 20},
	{Code: 21, Jt: 0, Jf: 23, K: 6},
	{Code: 48, Jt: 0, Jf: 0, K: 67},
	{Code: 84, Jt: 0, Jf: 0, K: 18},
	{Code: 21, Jt: 19, Jf: 20, K: 2},
	{Code: 21, Jt: 2, Jf: 0, K: 33024},
	{Code: 21, Jt: 1, Jf: 0, K: 34984},
	{Code: 21, Jt: 0, Jf: 17, K: 37120},
	{Code: 40, Jt: 0, Jf: 0, K: 16},
	{Code: 21, Jt: 0, Jf: 8, K: 2048},
	{Code: 48, Jt: 0, Jf: 0, K: 27},
	{Code: 21, Jt: 0, Jf: 13, K: 6},
	{Code: 40, Jt: 0, Jf: 0, K: 24},
	{Code: 69, Jt: 11, Jf: 0, K: 8191},
	{Code: 177, Jt: 0, Jf: 0, K: 18},
	{Code: 80, Jt: 0, Jf: 0, K: 31},
	{Code: 84, Jt: 0, Jf: 0, K: 18},
	{Code: 21, Jt: 6, Jf: 7, K: 2},
	{Code: 21, Jt: 0, Jf: 6, K: 34525},
	{Code: 48, Jt: 0, Jf: 0, K: 24},
	{Code: 21, Jt: 0, Jf: 4, K: 6},
	{Code: 48, Jt: 0, Jf: 0, K: 71},
	{Code: 84, Jt: 0, Jf: 0, K: 18},
	{Code: 21, Jt: 0, Jf: 1, K: 2},
	{Code: 6, Jt: 0, Jf: 0, K: 128},
	{Code: 6, Jt: 0, Jf: 0, K: 0},
}

func attachSharedSignalFilter(fd int) error {
	return syscall.AttachLsf(fd, sharedSignalSocketFilter)
}
