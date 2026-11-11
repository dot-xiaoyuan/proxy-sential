//go:build !linux && !darwin

package realtime

import "os"

func fileBirthMarker(_ string, _ os.FileInfo) string { return "" }
