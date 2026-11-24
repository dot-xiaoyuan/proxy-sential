//go:build !linux

package devicesignal

import (
	"context"
	"fmt"
	"net/netip"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

type Options struct {
	AuthenticatedRouters        func() map[sharedaccess.OutletKey]struct{}
	CollectorInstanceID         string
	CaptureScope                *normalized.CaptureScope
	Interface, Output, SensorID string
	Bucket                      time.Duration
	StateLiveness               time.Duration
	RouterProtocolsOnly         bool
	HandshakeOnly               bool
	SharedSignalsOnly           bool
	FlowSYNOnly                 bool
	SourceCIDRs                 []netip.Prefix
}

func Run(context.Context, Options) error {
	return fmt.Errorf("device signal capture requires Linux AF_PACKET")
}
