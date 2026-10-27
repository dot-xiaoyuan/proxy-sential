package fingerprint

import (
	"os"
	"strings"
)

// HistoryBackfillEnabled separates a library activation from historical work.
// Disabled jobs retain their progress and failure state; realtime observations
// continue using the active library without rebuilding the old inventory.
func HistoryBackfillEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_FINGERPRINT_HISTORY_BACKFILL")), "true")
}
