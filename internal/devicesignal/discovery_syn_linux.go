//go:build linux

package devicesignal

import "syscall"

// The existing control filter ends in RET 0. Its reject jumps now land
// on the first SYN instruction. Its full-length control returns stay intact.
func attachDiscoverySYNFilter(fd int) error {
	filter := make([]syscall.SockFilter, 0, len(routerProtocolSocketFilter)+len(discoverySYNProgram))
	filter = append(filter, routerProtocolSocketFilter[:len(routerProtocolSocketFilter)-1]...)
	for _, op := range discoverySYNProgram {
		filter = append(filter, syscall.SockFilter{Code: op.Code, Jt: op.Jt, Jf: op.Jf, K: op.K})
	}
	return syscall.AttachLsf(fd, filter)
}
