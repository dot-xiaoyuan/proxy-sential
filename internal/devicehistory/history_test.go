package devicehistory

import (
	"strings"
	"testing"
)

func TestProjectionPreservesChanges(t *testing.T) {
	for _, kind := range []string{"router", "profile", "shared", "discovery", "endpoint"} {
		q, _, err := source(Query{Kind: kind, ID: "id"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(q, "semantic") {
			t.Fatal(kind)
		}
		if kind != "endpoint" && !strings.Contains(q, "rule_version") {
			t.Fatalf("%s drops rules", kind)
		}
	}
	sql := groupedSQL("SELECT 1")
	if !strings.Contains(sql, "lag(semantic)") || !strings.Contains(sql, "PARTITION BY stream") || !strings.Contains(sql, "sum(changed)") {
		t.Fatal("must compress only consecutive observations per stream")
	}
}
