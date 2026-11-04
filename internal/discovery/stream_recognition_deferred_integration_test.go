package discovery

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// These cases need a migrated PostgreSQL. They assert the queue state that
// SQL mocks cannot model: no rewrite for a waiting realtime job, lane takeover
// for a historical job, and a bounded future run for completed/leased jobs.
func TestStreamRecognitionDeferredQueuePostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base := time.Now().UTC().Truncate(time.Second)
	suffix := fmt.Sprint(base.UnixNano())
	window := time.Minute
	scenarios := []struct {
		name       string
		mac        string
		processed  int64
		dirty      int64
		lane       int
		notBefore  time.Time
		leaseUntil time.Time
		updatedAt  time.Time
	}{
		{"pending-realtime", "02:00:00:00:0a:01", 0, 1, 0, base.Add(-time.Minute), time.Time{}, base.Add(-time.Hour)},
		{"pending-lane1", "02:00:00:00:0a:02", 0, 1, 1, base.Add(-time.Minute), time.Time{}, base.Add(-time.Hour)},
		{"completed", "02:00:00:00:0a:03", 1, 1, 0, base.Add(-time.Minute), time.Time{}, base.Add(-time.Hour)},
		{"leased", "02:00:00:00:0a:04", 0, 1, 0, base.Add(-time.Minute), base.Add(time.Minute), base.Add(-time.Hour)},
	}
	ids := make([]string, 0, len(scenarios))
	for _, s := range scenarios {
		id := "recog-deferred-" + suffix + "-" + s.name
		ids = append(ids, id)
		if _, err = db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,attributes) VALUES($1,$2,'endpoint',$3,$3,'{}')`, id, s.mac, base); err != nil {
			t.Fatalf("insert endpoint %s: %v", s.name, err)
		}
		// The endpoint trigger already created this job; configure that row
		// instead of inserting it a second time.
		result, err := db.ExecContext(ctx, `UPDATE endpoint_recognition_jobs SET dirty_generation=$2,processed_generation=$3,lane=$4,not_before=$5,lease_until=$6,updated_at=$7 WHERE endpoint_id=$1`,
			id, s.dirty, s.processed, s.lane, s.notBefore, s.leaseUntil, s.updatedAt)
		if err != nil {
			t.Fatalf("configure job %s: %v", s.name, err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			t.Fatalf("configure job %s: trigger-created row not found (affected=%d)", s.name, affected)
		}
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id)
			_, _ = db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, id)
		}
	})

	for index, s := range scenarios {
		id := ids[index]
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = markStreamRecognitionDirtyDeferred(ctx, tx, map[string]bool{s.mac: true}, window); err != nil {
			_ = tx.Rollback()
			t.Fatalf("%s: deferred mark: %v", s.name, err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}

		var dirty, processed int64
		var lane int
		var notBefore, updatedAt time.Time
		if err = db.QueryRowContext(ctx, `SELECT dirty_generation,processed_generation,lane,not_before,updated_at FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id).
			Scan(&dirty, &processed, &lane, &notBefore, &updatedAt); err != nil {
			t.Fatalf("%s: read job: %v", s.name, err)
		}

		switch s.name {
		case "pending-realtime":
			// A waiting realtime job must not be rewritten: same generation,
			// same scheduling time and same queue position.
			if dirty != s.dirty || processed != s.processed || lane != 0 {
				t.Fatalf("waiting job changed: dirty=%d processed=%d lane=%d", dirty, processed, lane)
			}
			if !notBefore.Equal(s.notBefore) || !updatedAt.Equal(s.updatedAt) {
				t.Fatalf("waiting job was rewritten: not_before=%s updated_at=%s", notBefore, updatedAt)
			}
		case "pending-lane1":
			if lane != 0 || dirty != s.dirty+1 {
				t.Fatalf("historical job was not taken over: lane=%d dirty=%d", lane, dirty)
			}
			if !notBefore.After(base.Add(window - 5*time.Second)) {
				t.Fatalf("historical job was not deferred: not_before=%s", notBefore)
			}
		default:
			if lane != 0 || dirty != s.dirty+1 {
				t.Fatalf("%s: unexpected state lane=%d dirty=%d", s.name, lane, dirty)
			}
			if !notBefore.After(base.Add(window - 5*time.Second)) {
				t.Fatalf("%s: not scheduled after window: not_before=%s", s.name, notBefore)
			}
		}
	}
}

// A correction in a later batch must promote a job that an earlier repeat
// observation deferred; the existing dirty function skips pending, unclaimed
// realtime rows, so promotion has to move not_before explicitly.
func TestStreamRecognitionDeferredPromotionPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base := time.Now().UTC().Truncate(time.Second)
	suffix := fmt.Sprint(base.UnixNano())
	mac := "02:00:00:00:0b:01"
	id := "recog-promote-" + suffix
	if _, err = db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,attributes) VALUES($1,$2,'endpoint',$3,$3,'{}')`, id, mac, base); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, id)
	})
	// Start from a completed job so the deferred mark opens a new generation
	// instead of leaving the trigger-created ready job untouched.
	if _, err = db.ExecContext(ctx, `UPDATE endpoint_recognition_jobs SET dirty_generation=1,processed_generation=1,lane=0,not_before=now(),lease_until='-infinity',updated_at=now() WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}

	run := func(apply func(*sql.Tx) error) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = apply(tx); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	read := func() (dirty, processed int64, lane int, notBefore time.Time) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `SELECT dirty_generation,processed_generation,lane,not_before FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id).
			Scan(&dirty, &processed, &lane, &notBefore); err != nil {
			t.Fatal(err)
		}
		return
	}

	run(func(tx *sql.Tx) error {
		return markStreamRecognitionDirtyDeferred(ctx, tx, map[string]bool{mac: true}, time.Minute)
	})
	dirty, processed, _, deferredUntil := read()
	if dirty != 2 || processed != 1 || !deferredUntil.After(time.Now().Add(30*time.Second)) {
		t.Fatalf("deferred state not established: dirty=%d processed=%d not_before=%s", dirty, processed, deferredUntil)
	}

	run(func(tx *sql.Tx) error {
		return markStreamRecognitionDirtyNow(ctx, tx, map[string]bool{mac: true})
	})
	dirty, processed, lane, promotedUntil := read()
	if dirty != 2 || processed != 1 || lane != 0 {
		t.Fatalf("immediate change altered generation: dirty=%d processed=%d lane=%d", dirty, processed, lane)
	}
	if promotedUntil.After(time.Now().Add(2 * time.Second)) {
		t.Fatalf("deferred job was not promoted: not_before=%s", promotedUntil)
	}
	var claimable int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_recognition_jobs WHERE endpoint_id=$1 AND processed_generation<dirty_generation AND not_before<=now() AND lease_until<now() AND lane=0`, id).Scan(&claimable); err != nil {
		t.Fatal(err)
	}
	if claimable != 1 {
		t.Fatalf("promoted job is not claimable: %d", claimable)
	}
}

// A failed job with a retry backoff must keep that backoff when a later
// visible change arrives; promotion is only for jobs delayed by coalescing,
// not for ones waiting out a failure.
func TestStreamRecognitionBackoffNotPromotedPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base := time.Now().UTC().Truncate(time.Second)
	suffix := fmt.Sprint(base.UnixNano())
	mac := "02:00:00:00:0c:01"
	id := "recog-backoff-" + suffix
	if _, err = db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,attributes) VALUES($1,$2,'endpoint',$3,$3,'{}')`, id, mac, base); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, id)
	})
	if _, err = db.ExecContext(ctx, `UPDATE endpoint_recognition_jobs SET dirty_generation=2,processed_generation=1,attempts=1,last_error='recognition failed',not_before=now()+interval '5 minutes',lane=0,lease_until='-infinity',updated_at=now() WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = markStreamRecognitionDirtyNow(ctx, tx, map[string]bool{mac: true}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var attempts int
	var lastError string
	var notBefore time.Time
	if err = db.QueryRowContext(ctx, `SELECT attempts,last_error,not_before FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id).
		Scan(&attempts, &lastError, &notBefore); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || lastError != "recognition failed" {
		t.Fatalf("retry state changed: attempts=%d last_error=%q", attempts, lastError)
	}
	if !notBefore.After(time.Now().Add(4 * time.Minute)) {
		t.Fatalf("retry backoff was promoted: not_before=%s", notBefore)
	}
	var claimable int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_recognition_jobs WHERE endpoint_id=$1 AND processed_generation<dirty_generation AND not_before<=now() AND lease_until<now() AND lane=0`, id).Scan(&claimable); err != nil {
		t.Fatal(err)
	}
	if claimable != 0 {
		t.Fatalf("backoff job became claimable: %d", claimable)
	}
}
