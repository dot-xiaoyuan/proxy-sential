package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// WorkErrorCode exposes actionable failures without logging source payloads,
// SQL parameters, credential-bearing URLs, or database connection strings.
func WorkErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, os.ErrPermission) {
		return "permission_denied"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "file_missing"
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		return "database_" + state.SQLState()
	}
	return fmt.Sprintf("%T", err)
}
