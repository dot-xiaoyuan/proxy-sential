//go:build !linux

package discovery

import (
	"context"
	"errors"
	"net/netip"
	"proxy-sentinel/internal/normalized"
)

func Capture(context.Context, string, string, Source, []netip.Prefix) error {
	return errors.New("passive capture requires Linux")
}

func CaptureConfigured(context.Context, string, string, Source, []netip.Prefix, CollectionConfig) error {
	return errors.New("passive capture requires Linux")
}

func CaptureStreamConfigured(context.Context, string, string, Source, []netip.Prefix, CollectionConfig, PassiveStreamJournal, *normalized.CaptureScope, func(CapturedSegment) error) error {
	return errors.New("passive capture requires Linux")
}
