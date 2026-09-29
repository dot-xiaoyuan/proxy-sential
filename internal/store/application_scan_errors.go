package store

import (
	"context"
	"errors"
	"strings"
)

func applicationScanResourceError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	message := strings.ToUpper(err.Error())
	return strings.Contains(message, "MEMORY_LIMIT_EXCEEDED") || strings.Contains(message, "TIMEOUT_EXCEEDED") || strings.Contains(message, "TIME LIMIT EXCEEDED")
}
