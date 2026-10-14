//go:build !linux

package discovery

import (
	"context"
	"errors"
	"net/netip"
)

func Capture(context.Context, string, string, Source, []netip.Prefix) error {
	return errors.New("passive capture requires Linux")
}
