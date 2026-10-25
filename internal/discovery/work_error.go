package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// WorkErrorCode exposes actionable failures without logging source payloads,
// SQL parameters, credential-bearing URLs, or database connection strings.
func WorkErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrDiscoveryContentConflict) {
		return "content_conflict"
	}
	if errors.Is(err, ErrDiscoveryLeaseLost) {
		return "lease_lost"
	}
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
		if state.SQLState() == "57014" {
			return "deadline_exceeded"
		}
		return "database_" + state.SQLState()
	}
	if strings.Contains(err.Error(), "TIMEOUT_EXCEEDED") || strings.Contains(err.Error(), "context deadline exceeded") {
		return "deadline_exceeded"
	}
	if strings.Contains(err.Error(), "discovery normalized write") {
		return "normalized_write_pending"
	}
	if strings.Contains(err.Error(), "clickhouse query failed:") {
		return "clickhouse_query_failed"
	}
	if strings.Contains(err.Error(), "clickhouse transport:") {
		return "clickhouse_transport_failed"
	}
	if strings.Contains(err.Error(), "discovery archive incomplete") {
		return "archive_incomplete"
	}
	return fmt.Sprintf("%T", err)
}
