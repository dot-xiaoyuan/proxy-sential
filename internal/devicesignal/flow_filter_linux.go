//go:build linux

package devicesignal

import "syscall"

// Only the flow ring accepts SYN-ACK in addition to initial SYN. The separate
// shared-signal collector keeps its initial-SYN filter. Each accepted frame is
// still truncated to 128 bytes before it reaches userspace.
var flowSocketFilter = func() []syscall.SockFilter {
	filter := append([]syscall.SockFilter(nil), sharedSignalSocketFilter...)
	for index := range filter {
		if filter[index].Code == 84 && filter[index].K == 18 {
			filter[index].K = 2
		}
	}
	return filter
}()

func attachFlowSignalFilter(fd int) error {
	return syscall.AttachLsf(fd, flowSocketFilter)
}
