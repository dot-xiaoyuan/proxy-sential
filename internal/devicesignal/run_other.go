//go:build !linux

package devicesignal

import (
	"context"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"time"
)

type Options struct {
	CollectorInstanceID         string
	CaptureScope                *normalized.CaptureScope
	Interface, Output, SensorID string
	Bucket                      time.Duration
}

func Run(context.Context, Options) error {
	return fmt.Errorf("device signal capture requires Linux AF_PACKET")
}
