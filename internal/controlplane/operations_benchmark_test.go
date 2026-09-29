package controlplane

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
)

// Compare scoped metadata reads against the current full operations reload.
// Run only on a disposable localhost benchmark database; no writes are issued.
func BenchmarkOperationsLoadScopes(b *testing.B) {
	dsn := os.Getenv("PROXY_SENTINEL_BENCHMARK_PG")
	if dsn == "" {
		b.Skip("isolated benchmark PostgreSQL required")
	}
	if !strings.Contains(dsn, "@127.0.0.1:") || !strings.Contains(dsn, "/sentinel_benchmark") {
		b.Fatal("disposable localhost fixture required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	for _, scope := range []string{"organization_only", "all_operations_with_history"} {
		b.Run(scope, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				state := &operationsState{}
				if scope == "organization_only" {
					doc := emptyOperationsDocument()
					err = loadOrganization(context.Background(), db, &doc)
				} else {
					err = state.reloadPostgres(context.Background(), db)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
