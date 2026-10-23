package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestPostgresRecognitionEntityHeartbeatGate(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	stamp := time.Now().UnixNano()
	id := fmt.Sprintf("mac:02:00:%02x:%02x:%02x:%02x", uint8(stamp>>24), uint8(stamp>>16), uint8(stamp>>8), uint8(stamp))
	defer pg.db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, id)
	start := time.Now().UTC().Truncate(time.Hour).Add(-2*time.Hour + time.Minute)
	if _, err = pg.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role,first_seen,last_seen,attributes) VALUES($1,'endpoint',$2,$2,'{}'::jsonb)`, id, start); err != nil {
		t.Fatal(err)
	}
	clear := func() int64 {
		t.Helper()
		var generation int64
		if err := pg.db.QueryRowContext(ctx, `UPDATE endpoint_recognition_jobs SET processed_generation=dirty_generation WHERE endpoint_id=$1 RETURNING dirty_generation`, id).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		return generation
	}
	check := func(want int64) {
		t.Helper()
		var generation int64
		if err := pg.db.QueryRowContext(ctx, `SELECT dirty_generation FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		if generation != want {
			t.Fatalf("recognition generation=%d, want %d", generation, want)
		}
	}
	initial := clear()
	if _, err = pg.db.ExecContext(ctx, `UPDATE endpoint_entities SET last_seen=$2 WHERE endpoint_id=$1`, id, start.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	check(initial)
	if _, err = pg.db.ExecContext(ctx, `UPDATE endpoint_entities SET last_seen=$2 WHERE endpoint_id=$1`, id, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	check(initial + 1)
	clear()
	if _, err = pg.db.ExecContext(ctx, `UPDATE endpoint_entities SET attributes='{"device_type":"router"}'::jsonb WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	check(initial + 2)
}
