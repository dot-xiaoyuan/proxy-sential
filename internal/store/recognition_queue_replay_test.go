package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRecognitionQueueCoalescesWithoutLosingInflightChangesPostgres(t *testing.T) {
	s := recognitionLeasePrivatePostgres(t)
	raw, err := os.ReadFile("../../migrations/postgres/100_recognition_queue_coalescing.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(`CREATE TRIGGER recognition_test_dirty AFTER UPDATE ON endpoint_entities FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job(); UPDATE endpoint_recognition_jobs SET updated_at=now()-interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err = s.pg.db.QueryRow(`SELECT updated_at FROM endpoint_recognition_jobs`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err = s.pg.db.Exec(`UPDATE endpoint_entities SET endpoint_id=endpoint_id`); err != nil {
			t.Fatal(err)
		}
	}
	var dirty int64
	var after time.Time
	if err = s.pg.db.QueryRow(`SELECT dirty_generation,updated_at FROM endpoint_recognition_jobs`).Scan(&dirty, &after); err != nil {
		t.Fatal(err)
	}
	if dirty != 1 || !before.Equal(after) {
		t.Fatalf("pending task moved or duplicated: %d %v %v", dirty, before, after)
	}
	job, found, err := s.claimRecognitionJob(context.Background(), "queue-test")
	if err != nil || !found {
		t.Fatalf("claim: %v %v", found, err)
	}
	if _, err = s.pg.db.Exec(`UPDATE endpoint_entities SET endpoint_id=endpoint_id`); err != nil {
		t.Fatal(err)
	}
	if err = s.finishRecognitionJob(context.Background(), job, nil); err != nil {
		t.Fatal(err)
	}
	var pending bool
	if err = s.pg.db.QueryRow(`SELECT dirty_generation>processed_generation FROM endpoint_recognition_jobs`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("inflight input update was lost")
	}
	job, found, err = s.claimRecognitionJob(context.Background(), "queue-test")
	if err != nil || !found {
		t.Fatalf("reclaim: %v %v", found, err)
	}
	if err = s.finishRecognitionJob(context.Background(), job, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(`UPDATE endpoint_entities SET endpoint_id=endpoint_id`); err != nil {
		t.Fatal(err)
	}
	if err = s.pg.db.QueryRow(`SELECT dirty_generation>processed_generation FROM endpoint_recognition_jobs`).Scan(&pending); err != nil || !pending {
		t.Fatalf("completed job not requeued: %v %v", pending, err)
	}
}
