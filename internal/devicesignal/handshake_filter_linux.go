//go:build linux

package devicesignal

import "syscall"

// handshakeSocketFilter converts the verified handshake program into the kernel socket filter.
func handshakeSocketFilter(program []bpfInsn) []syscall.SockFilter {
	out := make([]syscall.SockFilter, len(program))
	for i, insn := range program {
		out[i] = syscall.SockFilter{Code: insn.Code, Jt: insn.Jt, Jf: insn.Jf, K: insn.K}
	}
	return out
}

func attachHandshakeFilter(fd int, captureV2 bool) error {
	program := handshakeProgram
	if captureV2 {
		program = outletHandshakeProgram
	}
	return syscall.AttachLsf(fd, handshakeSocketFilter(program))
}
