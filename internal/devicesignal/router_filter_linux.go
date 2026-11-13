//go:build linux

package devicesignal

import (
	"fmt"
	"syscall"
)

// routerProtocolSocketFilter is compiled from discovery.DiscoveryCaptureFilter()
// for the 204 target discovery mode. It keeps ARP, DHCP, DNS-SD, NDP,
// WS-Discovery and the other configured device-control protocols in the
// kernel while excluding bulk client traffic. Untagged and up to two VLAN
// tags are accepted. Recompile when DefaultCollectionConfig changes.
var routerProtocolSocketFilter = []syscall.SockFilter{
	{Code: 40, Jt: 0, Jf: 0, K: 12},
	{Code: 21, Jt: 155, Jf: 0, K: 2054},
	{Code: 21, Jt: 154, Jf: 0, K: 35020},
	{Code: 21, Jt: 153, Jf: 0, K: 35130},
	{Code: 21, Jt: 0, Jf: 17, K: 34525},
	{Code: 48, Jt: 0, Jf: 0, K: 20},
	{Code: 21, Jt: 150, Jf: 0, K: 58},
	{Code: 21, Jt: 0, Jf: 108, K: 17},
	{Code: 40, Jt: 0, Jf: 0, K: 54},
	{Code: 21, Jt: 147, Jf: 0, K: 5353},
	{Code: 21, Jt: 146, Jf: 0, K: 1900},
	{Code: 21, Jt: 145, Jf: 0, K: 3702},
	{Code: 21, Jt: 144, Jf: 0, K: 161},
	{Code: 21, Jt: 143, Jf: 0, K: 162},
	{Code: 21, Jt: 142, Jf: 0, K: 546},
	{Code: 21, Jt: 141, Jf: 0, K: 547},
	{Code: 21, Jt: 140, Jf: 0, K: 137},
	{Code: 21, Jt: 139, Jf: 0, K: 5355},
	{Code: 21, Jt: 138, Jf: 0, K: 5683},
	{Code: 21, Jt: 137, Jf: 0, K: 47808},
	{Code: 40, Jt: 0, Jf: 0, K: 56},
	{Code: 21, Jt: 135, Jf: 121, K: 5353},
	{Code: 21, Jt: 0, Jf: 22, K: 2048},
	{Code: 48, Jt: 0, Jf: 0, K: 23},
	{Code: 21, Jt: 0, Jf: 128, K: 17},
	{Code: 40, Jt: 0, Jf: 0, K: 20},
	{Code: 69, Jt: 130, Jf: 0, K: 8191},
	{Code: 48, Jt: 0, Jf: 0, K: 14},
	{Code: 84, Jt: 0, Jf: 0, K: 15},
	{Code: 100, Jt: 0, Jf: 0, K: 2},
	{Code: 7, Jt: 0, Jf: 0, K: 5},
	{Code: 72, Jt: 0, Jf: 0, K: 14},
	{Code: 21, Jt: 124, Jf: 0, K: 5353},
	{Code: 21, Jt: 123, Jf: 0, K: 1900},
	{Code: 21, Jt: 122, Jf: 0, K: 3702},
	{Code: 21, Jt: 121, Jf: 0, K: 161},
	{Code: 21, Jt: 120, Jf: 0, K: 162},
	{Code: 21, Jt: 119, Jf: 0, K: 546},
	{Code: 21, Jt: 118, Jf: 0, K: 547},
	{Code: 21, Jt: 117, Jf: 0, K: 137},
	{Code: 21, Jt: 116, Jf: 0, K: 5355},
	{Code: 21, Jt: 115, Jf: 0, K: 5683},
	{Code: 21, Jt: 114, Jf: 0, K: 47808},
	{Code: 72, Jt: 0, Jf: 0, K: 16},
	{Code: 21, Jt: 112, Jf: 98, K: 5353},
	{Code: 21, Jt: 1, Jf: 0, K: 33024},
	{Code: 21, Jt: 0, Jf: 106, K: 34984},
	{Code: 40, Jt: 0, Jf: 0, K: 16},
	{Code: 21, Jt: 108, Jf: 0, K: 2054},
	{Code: 21, Jt: 107, Jf: 0, K: 35020},
	{Code: 21, Jt: 106, Jf: 0, K: 35130},
	{Code: 21, Jt: 0, Jf: 17, K: 34525},
	{Code: 48, Jt: 0, Jf: 0, K: 24},
	{Code: 21, Jt: 103, Jf: 0, K: 58},
	{Code: 21, Jt: 0, Jf: 61, K: 17},
	{Code: 40, Jt: 0, Jf: 0, K: 58},
	{Code: 21, Jt: 100, Jf: 0, K: 5353},
	{Code: 21, Jt: 99, Jf: 0, K: 1900},
	{Code: 21, Jt: 98, Jf: 0, K: 3702},
	{Code: 21, Jt: 97, Jf: 0, K: 161},
	{Code: 21, Jt: 96, Jf: 0, K: 162},
	{Code: 21, Jt: 95, Jf: 0, K: 546},
	{Code: 21, Jt: 94, Jf: 0, K: 547},
	{Code: 21, Jt: 93, Jf: 0, K: 137},
	{Code: 21, Jt: 92, Jf: 0, K: 5355},
	{Code: 21, Jt: 91, Jf: 0, K: 5683},
	{Code: 21, Jt: 90, Jf: 0, K: 47808},
	{Code: 40, Jt: 0, Jf: 0, K: 60},
	{Code: 21, Jt: 88, Jf: 74, K: 5353},
	{Code: 21, Jt: 0, Jf: 22, K: 2048},
	{Code: 48, Jt: 0, Jf: 0, K: 27},
	{Code: 21, Jt: 0, Jf: 81, K: 17},
	{Code: 40, Jt: 0, Jf: 0, K: 24},
	{Code: 69, Jt: 83, Jf: 0, K: 8191},
	{Code: 48, Jt: 0, Jf: 0, K: 18},
	{Code: 84, Jt: 0, Jf: 0, K: 15},
	{Code: 100, Jt: 0, Jf: 0, K: 2},
	{Code: 7, Jt: 0, Jf: 0, K: 6},
	{Code: 72, Jt: 0, Jf: 0, K: 18},
	{Code: 21, Jt: 77, Jf: 0, K: 5353},
	{Code: 21, Jt: 76, Jf: 0, K: 1900},
	{Code: 21, Jt: 75, Jf: 0, K: 3702},
	{Code: 21, Jt: 74, Jf: 0, K: 161},
	{Code: 21, Jt: 73, Jf: 0, K: 162},
	{Code: 21, Jt: 72, Jf: 0, K: 546},
	{Code: 21, Jt: 71, Jf: 0, K: 547},
	{Code: 21, Jt: 70, Jf: 0, K: 137},
	{Code: 21, Jt: 69, Jf: 0, K: 5355},
	{Code: 21, Jt: 68, Jf: 0, K: 5683},
	{Code: 21, Jt: 67, Jf: 0, K: 47808},
	{Code: 72, Jt: 0, Jf: 0, K: 20},
	{Code: 21, Jt: 65, Jf: 51, K: 5353},
	{Code: 21, Jt: 1, Jf: 0, K: 33024},
	{Code: 21, Jt: 0, Jf: 59, K: 34984},
	{Code: 40, Jt: 0, Jf: 0, K: 20},
	{Code: 21, Jt: 61, Jf: 0, K: 2054},
	{Code: 21, Jt: 60, Jf: 0, K: 35020},
	{Code: 21, Jt: 59, Jf: 0, K: 35130},
	{Code: 21, Jt: 0, Jf: 21, K: 34525},
	{Code: 48, Jt: 0, Jf: 0, K: 28},
	{Code: 21, Jt: 56, Jf: 0, K: 58},
	{Code: 21, Jt: 0, Jf: 14, K: 17},
	{Code: 40, Jt: 0, Jf: 0, K: 62},
	{Code: 21, Jt: 53, Jf: 0, K: 5353},
	{Code: 21, Jt: 52, Jf: 0, K: 1900},
	{Code: 21, Jt: 51, Jf: 0, K: 3702},
	{Code: 21, Jt: 50, Jf: 0, K: 161},
	{Code: 21, Jt: 49, Jf: 0, K: 162},
	{Code: 21, Jt: 48, Jf: 0, K: 546},
	{Code: 21, Jt: 47, Jf: 0, K: 547},
	{Code: 21, Jt: 46, Jf: 0, K: 137},
	{Code: 21, Jt: 45, Jf: 0, K: 5355},
	{Code: 21, Jt: 44, Jf: 0, K: 5683},
	{Code: 21, Jt: 43, Jf: 0, K: 47808},
	{Code: 40, Jt: 0, Jf: 0, K: 64},
	{Code: 21, Jt: 41, Jf: 27, K: 5353},
	{Code: 21, Jt: 40, Jf: 0, K: 0},
	{Code: 21, Jt: 39, Jf: 0, K: 43},
	{Code: 21, Jt: 38, Jf: 0, K: 44},
	{Code: 21, Jt: 37, Jf: 33, K: 60},
	{Code: 21, Jt: 0, Jf: 32, K: 2048},
	{Code: 48, Jt: 0, Jf: 0, K: 31},
	{Code: 21, Jt: 0, Jf: 30, K: 17},
	{Code: 40, Jt: 0, Jf: 0, K: 28},
	{Code: 69, Jt: 32, Jf: 0, K: 8191},
	{Code: 48, Jt: 0, Jf: 0, K: 22},
	{Code: 84, Jt: 0, Jf: 0, K: 15},
	{Code: 100, Jt: 0, Jf: 0, K: 2},
	{Code: 7, Jt: 0, Jf: 0, K: 7},
	{Code: 72, Jt: 0, Jf: 0, K: 22},
	{Code: 21, Jt: 26, Jf: 0, K: 5353},
	{Code: 21, Jt: 25, Jf: 0, K: 1900},
	{Code: 21, Jt: 24, Jf: 0, K: 3702},
	{Code: 21, Jt: 23, Jf: 0, K: 161},
	{Code: 21, Jt: 22, Jf: 0, K: 162},
	{Code: 21, Jt: 21, Jf: 0, K: 546},
	{Code: 21, Jt: 20, Jf: 0, K: 547},
	{Code: 21, Jt: 19, Jf: 0, K: 137},
	{Code: 21, Jt: 18, Jf: 0, K: 5355},
	{Code: 21, Jt: 17, Jf: 0, K: 5683},
	{Code: 21, Jt: 16, Jf: 0, K: 47808},
	{Code: 72, Jt: 0, Jf: 0, K: 24},
	{Code: 21, Jt: 14, Jf: 0, K: 5353},
	{Code: 21, Jt: 13, Jf: 0, K: 1900},
	{Code: 21, Jt: 12, Jf: 0, K: 3702},
	{Code: 21, Jt: 11, Jf: 0, K: 161},
	{Code: 21, Jt: 10, Jf: 0, K: 162},
	{Code: 21, Jt: 9, Jf: 0, K: 546},
	{Code: 21, Jt: 8, Jf: 0, K: 547},
	{Code: 21, Jt: 7, Jf: 0, K: 137},
	{Code: 21, Jt: 6, Jf: 0, K: 5355},
	{Code: 21, Jt: 5, Jf: 0, K: 5683},
	{Code: 21, Jt: 4, Jf: 0, K: 47808},
	{Code: 32, Jt: 0, Jf: 0, K: 2},
	{Code: 21, Jt: 0, Jf: 3, K: 214748364},
	{Code: 40, Jt: 0, Jf: 0, K: 0},
	{Code: 21, Jt: 0, Jf: 1, K: 256},
	{Code: 6, Jt: 0, Jf: 0, K: 262144},
	{Code: 6, Jt: 0, Jf: 0, K: 0},
}

func attachRouterProtocolFilter(fd int) error {
	filter, err := routerProtocolFilterForARP(arpSignalsEnabled())
	if err != nil {
		return err
	}
	return syscall.AttachLsf(fd, filter)
}

// The compiled discovery filter includes ARP for the 204 device-center mode.
// Router-sidecar does not emit ARP unless its explicit source switch is on.
// Change only the three ARP accept branches; all other protocol offsets and
// jumps remain byte-for-byte identical to the reviewed generated filter.
func routerProtocolFilterForARP(enabled bool) ([]syscall.SockFilter, error) {
	if enabled {
		return routerProtocolSocketFilter, nil
	}
	filter := append([]syscall.SockFilter(nil), routerProtocolSocketFilter...)
	branches := 0
	for i := range filter {
		if filter[i].Code != syscall.BPF_JMP|syscall.BPF_JEQ|syscall.BPF_K || filter[i].K != 0x0806 {
			continue
		}
		if filter[i].Jf != 0 || filter[i].Jt == 0 {
			return nil, fmt.Errorf("router ARP filter branch has changed")
		}
		filter[i].Jt = 0
		branches++
	}
	if branches != 3 {
		return nil, fmt.Errorf("router ARP filter has %d branches, want 3", branches)
	}
	return filter, nil
}
