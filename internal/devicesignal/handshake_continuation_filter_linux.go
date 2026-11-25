//go:build linux

package devicesignal

import (
	"fmt"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// All shards are configured while still unbound. A failure closes the whole
// new set, leaving the caller in control of its main capture descriptor.
func openHandshakeContinuationSockets(ifindex int, keys map[handshakeKey]struct{}) ([]int, error) {
	programs, err := continuationFilterPrograms(keys)
	if err != nil {
		return nil, err
	}
	var sockets []int
	closeOnError := func(err error) ([]int, error) {
		for _, fd := range sockets {
			_ = unix.Close(fd)
		}
		return nil, fmt.Errorf("open ClientHello continuation capture: %w", err)
	}
	for _, program := range programs {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return closeOnError(err)
		}
		sockets = append(sockets, fd)
		if err := attachContinuationProgram(fd, program); err != nil {
			return closeOnError(err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
			return closeOnError(err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 512<<10); err != nil {
			return closeOnError(err)
		}
	}
	for _, fd := range sockets {
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
			return closeOnError(err)
		}
	}
	return sockets, nil
}

func attachContinuationProgram(fd int, program []bpf.Instruction) error {
	raw, err := bpf.Assemble(program)
	if err != nil {
		return err
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filters[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]})
}
