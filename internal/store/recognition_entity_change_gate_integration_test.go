package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestPostgresRecognitionEntityHeartbeatGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pg := privateMigratedTestPostgres(t)
	flush := func() {
		t.Helper()
		if _, err := (&DBStore{pg: pg}).flushRecognitionDirtyLog(ctx); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Now().UnixNano()
	id := fmt.Sprintf("mac:02:00:%02x:%02x:%02x:%02x", uint8(stamp>>24), uint8(stamp>>16), uint8(stamp>>8), uint8(stamp))
	start := time.Now().UTC().Truncate(time.Hour).Add(-2*time.Hour + time.Minute)
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role,first_seen,last_seen,attributes) VALUES($1,'endpoint',$2,$2,'{}'::jsonb)`, id, start); err != nil {
		t.Fatal(err)
	}
	clear := func() int64 {
		t.Helper()
		flush()
		var generation int64
		if err := pg.db.QueryRowContext(ctx, `UPDATE endpoint_recognition_jobs SET processed_generation=dirty_generation WHERE endpoint_id=$1 RETURNING dirty_generation`, id).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		return generation
	}
	check := func(want int64) {
		t.Helper()
		flush()
		var generation int64
		if err := pg.db.QueryRowContext(ctx, `SELECT dirty_generation FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		if generation != want {
			t.Fatalf("recognition generation=%d, want %d", generation, want)
		}
	}
	initial := clear()
	if _, err := pg.db.ExecContext(ctx, `UPDATE endpoint_entities SET last_seen=$2 WHERE endpoint_id=$1`, id, start.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	check(initial)
	if _, err := pg.db.ExecContext(ctx, `UPDATE endpoint_entities SET last_seen=$2 WHERE endpoint_id=$1`, id, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	check(initial + 1)
	clear()
	if _, err := pg.db.ExecContext(ctx, `UPDATE endpoint_entities SET attributes='{"device_type":"router"}'::jsonb WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	check(initial + 2)
}
