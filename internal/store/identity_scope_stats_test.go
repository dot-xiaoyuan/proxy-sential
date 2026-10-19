package store

import (
	"regexp"
	"strings"
	"testing"
)

// The apply transaction must not add to the scope's account and session totals. Those totals are
// read-side statistics; accumulating them in the transaction that also advances processed_sequence
// made every apply queue on the scope row (313 ms per statement on the field).
func TestApplyStatementDoesNotAccumulateStatistics(t *testing.T) {
	statement := applyScopeProgressSQL
	for _, forbidden := range []string{"accounts=accounts+", "sessions=sessions+", "statistics_at=now()"} {
		if strings.Contains(statement, forbidden) {
			t.Fatalf("apply statement still accumulates %q", forbidden)
		}
	}
	for _, required := range []string{"pending_records=pending_records-", "processed_sequence=", "lease_until=NULL", "current_generation="} {
		if !strings.Contains(statement, required) {
			t.Fatalf("apply statement lost required progress %q", required)
		}
	}
}

// Statistics are written by a separate statement keyed by scope, outside the apply transaction.
func TestScopeStatisticsStatementIsSeparateAndKeyed(t *testing.T) {
	if !regexp.MustCompile(`INSERT INTO identity_scope_statistics\(scope_key,accounts,sessions,counted_sequence,statistics_at\)`).MatchString(scopeStatisticsAddSQL) {
		t.Fatalf("statistics statement not keyed insert: %s", scopeStatisticsAddSQL)
	}
	if !strings.Contains(scopeStatisticsAddSQL, "ON CONFLICT(scope_key) DO UPDATE") {
		t.Fatal("statistics upsert missing conflict target")
	}
}

// Totals are accumulated per applied batch and the row remembers the last batch it counted, so a
// retried or replayed apply adds nothing twice, and a lost statistics write is recovered by the next.
func TestScopeStatisticsCountsEachBatchOnce(t *testing.T) {
	if !strings.Contains(scopeStatisticsAddSQL, "WHERE identity_scope_statistics.counted_sequence < EXCLUDED.counted_sequence") {
		t.Fatal("statistics must add only batches newer than the last counted one")
	}
	if !strings.Contains(scopeStatisticsAddSQL, "counted_sequence") {
		t.Fatal("statistics row must record the last counted batch sequence")
	}
}
