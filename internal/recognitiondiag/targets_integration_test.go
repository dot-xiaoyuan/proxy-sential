package recognitiondiag

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The fixture shadows application tables with CTEs: it exercises the actual
// observer ownership join without writing synthetic traffic to the database.
func TestFreshTargetOwnershipSQLReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL required for read-only SQL replay")
	}
	raw, err := os.ReadFile("testdata/targets_replay.sql")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, strings.ReplaceAll(string(raw), "/* TARGETS_LATERAL */", TargetsLateralSQL))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		var expectedRaw, actualRaw []byte
		if err := rows.Scan(&id, &expectedRaw, &actualRaw); err != nil {
			t.Fatal(err)
		}
		var expected, actual []Target
		if err := json.Unmarshal(expectedRaw, &expected); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(actualRaw, &actual); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("%s: got %+v, want %+v", id, actual, expected)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 8 {
		t.Fatalf("incomplete replay: %d cases", count)
	}
}
