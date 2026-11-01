//go:build linux

package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func fileBirthTime(f *os.File) (time.Time, bool) {
	var stat unix.Statx_t
	if err := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_BTIME, &stat); err != nil || stat.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}, false
	}
	return time.Unix(stat.Btime.Sec, int64(stat.Btime.Nsec)).UTC(), true
}
