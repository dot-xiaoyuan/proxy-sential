//go:build !linux && !darwin

package main

import (
	"os"
	"time"
)

func fileBirthTime(_ *os.File) (time.Time, bool) { return time.Time{}, false }
