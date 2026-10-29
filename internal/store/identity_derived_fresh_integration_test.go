package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

func TestIdentityDerivedFreshCancellationIsAuditedAndBounded(t *testing.T) {
	db := stdlib.OpenDB(*identityDerivedReadyTestConfig(t))
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	schema := fmt.Sprintf("identity_cancel_test_%d", time.Now().UnixNano())
	if _, err = tx.ExecContext(ctx, `CREATE SCHEMA `+schema+`; SET LOCAL search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"testdata/identity_derived_fresh_setup.sql", "../../migrations/postgres/199_identity_derived_fresh_cutover.sql", "../../migrations/postgres/200_identity_derived_cancel_state_validation.sql"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	query, args := identityDerivedCandidateQuery("ncu", 0, time.Date(2026, 10, 29, 5, 11, 29, 0, time.UTC))
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("boundary event disappeared")
	}
	values := make([]any, 8)
	ptrs := make([]any, 8)
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err = rows.Scan(ptrs...); err != nil {
		t.Fatal(err)
	}
	if values[0] != "e-boundary" {
		t.Fatalf("wrong next candidate: %v", values[0])
	}
	rows.Close()
	body, err := os.ReadFile("testdata/identity_derived_fresh_assert.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, string(body)); err != nil {
		t.Fatal(err)
	}

}
