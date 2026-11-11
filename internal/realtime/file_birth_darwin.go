//go:build darwin

package realtime

import (
	"fmt"
	"os"
	"syscall"
)

func fileBirthMarker(_ string, info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Birthtimespec.Sec == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%09d", stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec)
}
