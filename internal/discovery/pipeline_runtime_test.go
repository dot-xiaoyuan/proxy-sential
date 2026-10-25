package discovery

import (
	"context"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"sync"
	"testing"
	"time"
)

func TestPipelineModeIsolation(t *testing.T) {
	for _, tc := range []struct {
		mode                      string
		capture, active, generate bool
	}{
		{"all", true, true, true}, {"passive", true, false, false}, {"consume-only", false, false, false},
	} {
		o, err := NewWorkerOptions(tc.mode, 1)
		if err != nil || o.Capture() != tc.capture || o.Active() != tc.active || o.GenerateBackfill() != tc.generate {
			t.Fatalf("mode %s: %+v %v", tc.mode, o, err)
		}
	}
	for _, mode := range []string{"disabled", "consume", "ALL"} {
		if _, err := NewWorkerOptions(mode, 2); err == nil {
			t.Fatalf("accepted mode %s", mode)
		}
	}
	for _, n := range []int{0, 3, -1} {
		if _, err := NewWorkerOptions("all", n); err == nil {
			t.Fatalf("accepted concurrency %d", n)
		}
	}
}

func TestPipelineObserverConcurrentSegments(t *testing.T) {
	o := newPipelineObserver()
	ctx := WithPipelineObserver(context.Background(), o)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				ObserveStage(ctx, "commit", time.Now(), nil)
				recordPipelineResult(ctx, 50, nil, "")
			}
		}()
	}
	wg.Wait()
	if o.processed != 40000 || o.completedSegments != 800 || o.stages["commit"].Calls != 800 {
		t.Fatalf("lost progress: %+v", o)
	}
}

func TestPipelineReadFailureIsNotAnEmptyQueue(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m.ExpectQuery("FROM discovery_pipeline_summary").WillReturnError(fmt.Errorf("database unavailable"))
	if _, err = (Repository{DB: db}).PipelineStatus(context.Background()); err == nil {
		t.Fatal("failed read reported an empty queue")
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPipelineStateUsesSegmentProgressAndFreshHeartbeat(t *testing.T) {
	now := time.Now().UTC()
	past := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	base := PipelineLane{Lane: "realtime", PendingBatches: 3, EligibleBatches: 3, UpdatedAt: now, HeartbeatAt: past(time.Second), StartedAt: past(time.Minute * 2), LastProgressAt: past(time.Second), OldestPendingAt: past(time.Hour)}
	for _, tc := range []struct {
		name  string
		alter func(*PipelineLane)
		want  string
	}{
		{"advancing old batch", func(*PipelineLane) {}, "delayed"},
		{"stopped", func(s *PipelineLane) { s.HeartbeatAt = past(16 * time.Second) }, "interrupted"},
		{"alive but stuck", func(s *PipelineLane) { s.LastProgressAt = past(61 * time.Second) }, "stalled"},
		{"recent retry", func(s *PipelineLane) {
			s.LastErrorAt = past(time.Second)
			s.LastProgressAt = past(2 * time.Second)
			s.LastError = "deadline_exceeded"
		}, "retrying"},
		{"historical failure", func(s *PipelineLane) { s.FailedBatches = 1; s.LastErrorAt = past(time.Hour) }, "delayed"},
		{"idle", func(s *PipelineLane) { s.PendingBatches = 0; s.EligibleBatches = 0; s.OldestPendingAt = nil }, "idle"},
		{"fresh processing", func(s *PipelineLane) { s.OldestPendingAt = past(time.Second) }, "processing"},
		{"stale summary", func(s *PipelineLane) { s.UpdatedAt = now.Add(-16 * time.Second) }, "stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.alter(&s)
			if got := s.Status(now); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
