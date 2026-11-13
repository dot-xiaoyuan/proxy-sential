//go:build linux

package devicesignal

import (
	"syscall"
	"testing"
)

func TestCaptureReceiveBufferReadsEffectiveKernelLimit(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	effective, err := setCaptureReceiveBuffer(fd, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if effective < 64<<10 || effective > 128<<10 {
		t.Fatalf("effective receive buffer=%d outside the requested bounded size", effective)
	}
}
