//go:build linux

package devicesignal

import "syscall"

// handshakeSocketFilter converts the verified handshake program into the kernel socket filter.
var handshakeSocketFilter = func() []syscall.SockFilter {
	out := make([]syscall.SockFilter, len(handshakeProgram))
	for i, insn := range handshakeProgram {
		out[i] = syscall.SockFilter{Code: insn.Code, Jt: insn.Jt, Jf: insn.Jf, K: insn.K}
	}
	return out
}()

func attachHandshakeFilter(fd int) error {
	return syscall.AttachLsf(fd, handshakeSocketFilter)
}
