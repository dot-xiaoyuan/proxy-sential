//go:build linux

package realtime

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func fileBirthMarker(path string, info os.FileInfo) string {
	old, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	var current unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_BTIME|unix.STATX_INO, &current); err != nil ||
		current.Mask&unix.STATX_BTIME == 0 || current.Btime.Sec == 0 ||
		current.Ino != old.Ino || current.Dev_major != unix.Major(uint64(old.Dev)) || current.Dev_minor != unix.Minor(uint64(old.Dev)) {
		return ""
	}
	return fmt.Sprintf("%d.%09d", current.Btime.Sec, current.Btime.Nsec)
}
