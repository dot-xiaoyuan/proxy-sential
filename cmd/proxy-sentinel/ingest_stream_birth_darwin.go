//go:build darwin

package main

import (
	"os"
	"syscall"
	"time"
)

func fileBirthTime(f *os.File) (time.Time, bool) {
	info, err := f.Stat()
	if err != nil {
		return time.Time{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Birthtimespec.Sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec).UTC(), true
}
