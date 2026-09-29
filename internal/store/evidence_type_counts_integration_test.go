package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestEvidenceTypeCountsReplayInsertUpsertUpdateDelete(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := fmt.Sprintf("count-replay-%d", time.Now().UnixNano())
	a, b := id+"a", id+"b"
	defer db.ExecContext(ctx, "DELETE FROM evidence WHERE evidence_id=$1", id)
	defer db.ExecContext(ctx, "DELETE FROM evidence_type_counts WHERE type IN ($1,$2)", a, b)
	check := func(typ string, want int) {
		t.Helper()
		var got int
		err := db.QueryRowContext(ctx, "SELECT evidence_count FROM evidence_type_counts WHERE type=$1", typ).Scan(&got)
		if err != nil || got != want {
			t.Fatalf("%s count=%d want=%d err=%v", typ, got, want, err)
		}
	}
	query := `INSERT INTO evidence(evidence_id,ip,type,"window",score,confidence,severity,reason,created_at) VALUES($1,'192.0.2.1',$2,'1h',1,.5,'low','test',now()) ON CONFLICT(evidence_id) DO UPDATE SET reason=EXCLUDED.reason`
	for n := 0; n < 2; n++ {
		if _, err = db.ExecContext(ctx, query, id, a); err != nil {
			t.Fatal(err)
		}
	}
	check(a, 1)
	if _, err = db.ExecContext(ctx, "UPDATE evidence SET type=$2 WHERE evidence_id=$1", id, b); err != nil {
		t.Fatal(err)
	}
	check(a, 0)
	check(b, 1)
	if _, err = db.ExecContext(ctx, "DELETE FROM evidence WHERE evidence_id=$1", id); err != nil {
		t.Fatal(err)
	}
	check(b, 0)
}
