package store

import (
	"os"
	"strconv"
	"strings"
)

// PostgresPoolLimit applies the deployment-wide lower bound to one SQL pool.
// The environment variable can only reduce a caller's role-specific default;
// it cannot silently increase the aggregate connection budget.
func PostgresPoolLimit(defaultLimit int) int {
	if defaultLimit < 1 {
		defaultLimit = 1
	}
	configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_POSTGRES_MAX_OPEN_CONNS")))
	if err == nil && configured > 0 && configured < defaultLimit {
		return configured
	}
	return defaultLimit
}
