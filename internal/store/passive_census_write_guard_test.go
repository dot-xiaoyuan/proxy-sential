package store

import (
	"strings"
	"testing"
)

func TestCensusIdentifierUpsertsBoundRepeatedRefresh(t *testing.T) {
	for name, query := range map[string]string{
		"current": censusCurrentUpsert,
		"bucket":  censusBucketUpsert,
	} {
		t.Run(name, func(t *testing.T) {
			table := "passive_census_identifier_" + name
			if name == "bucket" {
				table = "passive_census_identifier_5m"
			}
			for _, guard := range []string{
				"EXCLUDED.first_seen<" + table + ".first_seen",
				"EXCLUDED.last_seen>=" + table + ".last_seen+interval '60 seconds'",
				"EXCLUDED.last_seen=" + table + ".last_seen AND EXCLUDED.last_event_id>" + table + ".last_event_id",
			} {
				if !strings.Contains(query, guard) {
					t.Fatalf("missing refresh guard %q", guard)
				}
			}
		})
	}
}
