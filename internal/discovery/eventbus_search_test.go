package discovery

import (
	"strings"
	"testing"
)

func TestEventBusAddressSearchIncludesActiveStreamFacts(t *testing.T) {
	for _, column := range []string{"ip", "mac"} {
		clause := eventBusAddressSearchClause(column, "$2")
		for _, fragment := range []string{
			"discovery_service_facts_shadow",
			"stream_discovery_facts",
			"stream_source_cutovers",
			"cut.state='active'",
			"f." + column + "=$2",
		} {
			if !strings.Contains(clause, fragment) {
				t.Errorf("%s search missing %q: %s", column, fragment, clause)
			}
		}
	}
}
