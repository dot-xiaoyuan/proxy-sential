package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestApplicationScanResourceErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{{errors.New("Code: 241 MEMORY_LIMIT_EXCEEDED"), true}, {errors.New("TIMEOUT_EXCEEDED"), true}, {fmt.Errorf("request failed: %w", context.DeadlineExceeded), true}, {context.Canceled, false}, {errors.New("connection refused"), false}, {errors.New("authentication failed"), false}} {
		if got := applicationScanResourceError(tc.err); got != tc.want {
			t.Fatalf("%v: got %v", tc.err, got)
		}
	}
}
