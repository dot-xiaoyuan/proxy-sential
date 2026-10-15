//go:build linux

package discovery

import (
	"bytes"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

func attachDiscoveryFilter(fd int, config CollectionConfig) error {
	raw, err := exec.Command("tcpdump", "-ddd", "-y", "EN10MB", "-s", "65535", CaptureFilterFor(config)).Output()
	if err != nil {
		return fmt.Errorf("compile discovery BPF: %w", err)
	}
	reader := bytes.NewReader(raw)
	var count int
	if _, err = fmt.Fscan(reader, &count); err != nil || count < 1 || count > 4096 {
		return fmt.Errorf("invalid discovery BPF length")
	}
	filters := make([]syscall.SockFilter, count)
	for i := range filters {
		if _, err = fmt.Fscan(reader, &filters[i].Code, &filters[i].Jt, &filters[i].Jf, &filters[i].K); err != nil {
			return err
		}
	}
	program := syscall.SockFprog{Len: uint16(count), Filter: &filters[0]}
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, uintptr(unsafe.Pointer(&program)), unsafe.Sizeof(program), 0)
	if e != 0 {
		return e
	}
	return nil
}
