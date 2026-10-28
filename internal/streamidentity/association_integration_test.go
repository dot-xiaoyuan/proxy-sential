package streamidentity

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// CTE fixtures exercise the production resolver without creating tables,
// inserting synthetic traffic or depending on the installed schema.
func TestScopedAssociationSQLReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL required for read-only SQL replay")
	}
	raw, err := os.ReadFile("testdata/association_replay.sql")
	if err != nil {
		t.Fatal(err)
	}
	query := strings.ReplaceAll(string(raw), "/* MAC_LATERAL */", MACLateralSQL)
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
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		var expected, actual sql.NullString
		if err := rows.Scan(&id, &expected, &actual); err != nil {
			t.Fatal(err)
		}
		count++
		if actual != expected {
			t.Errorf("%s: got %+v, want %+v", id, actual, expected)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 30 {
		t.Fatalf("incomplete replay: %d cases", count)
	}
}
