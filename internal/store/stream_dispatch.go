package store

import (
	"context"
	"errors"
	"sync/atomic"

	"proxy-sentinel/internal/streamlog"
)

type streamDispatchKey struct{}
type streamDispatch struct{ started atomic.Bool }

func trackStreamDispatch(ctx context.Context) (context.Context, *streamDispatch) {
	tracker := &streamDispatch{}
	return context.WithValue(ctx, streamDispatchKey{}, tracker), tracker
}

func classifyUnsentStreamLane(err error, tracker *streamDispatch) error {
	if err != nil && tracker != nil && !tracker.started.Load() &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return &streamlog.UnsentLaneError{Cause: err}
	}
	return err
}
