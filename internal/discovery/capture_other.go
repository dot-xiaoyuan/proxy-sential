//go:build !linux

package discovery

import (
	"context"
	"errors"
)

func Capture(context.Context, string, string, Source) error {
	return errors.New("passive capture requires Linux")
}
