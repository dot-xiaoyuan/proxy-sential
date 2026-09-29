package store

import (
	"strings"
	"testing"
)

func TestApplicationConnectionRebuildPrunesBeforeDeduplication(t *testing.T) {
	query := applicationConnectionRebuildSQL(42, []string{"('sensor','','connection')"})
	for _, required := range []string{"PREWHERE", "application_connection_observations_v2 FINAL", "toUInt64(42)"} {
		if !strings.Contains(query, required) {
			t.Fatalf("connection rebuild query is missing %q: %s", required, query)
		}
	}
	if !strings.Contains(query, "FROM application_connection_observations_v2") {
		t.Fatalf("connection rebuild must use the fine-grained lookup model: %s", query)
	}
	if strings.Contains(query, "argMax(") {
		t.Fatalf("fine-grained FINAL lookup must not retain the two-stage aggregation: %s", query)
	}
}
