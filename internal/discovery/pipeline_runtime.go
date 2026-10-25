package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type WorkerOptions struct {
	Mode            string
	RealtimeWorkers int
}

func NewWorkerOptions(mode string, workers int) (WorkerOptions, error) {
	if mode == "" {
		mode = "all"
	}
	if mode != "all" && mode != "passive" && mode != "consume-only" {
		return WorkerOptions{}, fmt.Errorf("invalid discovery mode %q", mode)
	}
	if workers < 1 || workers > 2 {
		return WorkerOptions{}, fmt.Errorf("discovery realtime workers must be 1 or 2")
	}
	return WorkerOptions{mode, workers}, nil
}
func (o WorkerOptions) Capture() bool          { return o.Mode != "consume-only" }
func (o WorkerOptions) Active() bool           { return o.Mode == "all" }
func (o WorkerOptions) GenerateBackfill() bool { return o.Mode == "all" }

type PipelineLane struct {
	PauseReason       string                `json:"pause_reason,omitempty"`
	CompletedSegments int64                 `json:"completed_segments"`
	TimeoutFailures   int64                 `json:"timeout_failures"`
	EventsPerSecond   float64               `json:"events_per_second"`
	Lane              string                `json:"lane"`
	PendingBatches    int64                 `json:"pending_batches"`
	EligibleBatches   int64                 `json:"eligible_batches"`
	FailedBatches     int64                 `json:"historical_failed_batches"`
	RemainingEvents   int64                 `json:"remaining_events"`
	OldestPendingAt   *time.Time            `json:"oldest_pending_at,omitempty"`
	LastProgressAt    *time.Time            `json:"last_progress_at,omitempty"`
	HeartbeatAt       *time.Time            `json:"heartbeat_at,omitempty"`
	StartedAt         *time.Time            `json:"started_at,omitempty"`
	UpdatedAt         time.Time             `json:"updated_at"`
	ProcessedEvents   int64                 `json:"processed_events"`
	Retries           int64                 `json:"retries"`
	LastErrorAt       *time.Time            `json:"last_error_at,omitempty"`
	LastError         string                `json:"last_error,omitempty"`
	ErrorStage        string                `json:"error_stage,omitempty"`
	State             string                `json:"status"`
	Stages            map[string]StageStats `json:"stages,omitempty"`
}

func (s PipelineLane) Status(now time.Time) string {
	if s.UpdatedAt.IsZero() || now.Sub(s.UpdatedAt) > 15*time.Second {
		return "stale"
	}
	if s.HeartbeatAt == nil || now.Sub(*s.HeartbeatAt) > 15*time.Second {
		return "interrupted"
	}
	if s.PauseReason != "" {
		return "paused"
	}
	if s.PendingBatches == 0 {
		return "idle"
	}
	progress := s.LastProgressAt
	if progress == nil || (s.StartedAt != nil && progress.Before(*s.StartedAt)) {
		progress = s.StartedAt
	}
	if s.EligibleBatches > 0 && (progress == nil || now.Sub(*progress) > 60*time.Second) {
		return "stalled"
	}
	if s.LastError != "" && s.LastErrorAt != nil && now.Sub(*s.LastErrorAt) < 60*time.Second && (s.LastProgressAt == nil || s.LastErrorAt.After(*s.LastProgressAt)) {
		return "retrying"
	}
	if s.OldestPendingAt != nil && now.Sub(*s.OldestPendingAt) > 5*time.Second {
		return "delayed"
	}
	return "processing"
}

type PipelineStatus struct {
	Status    string             `json:"status"`
	Lanes     []PipelineLane     `json:"lanes"`
	Consumers []PipelineConsumer `json:"consumers"`
}

func (r Repository) PipelineStatus(ctx context.Context) (PipelineStatus, error) {
	// Runtime rows contain bounded per-role counters; no retained task aggregation.
	rows, err := r.DB.QueryContext(ctx, `SELECT s.lane,s.pending_batches,s.eligible_batches,s.failed_batches,s.remaining_events,s.oldest_pending_at,greatest(s.last_progress_at,c.last_progress_at),s.updated_at,
 c.heartbeat_at,c.started_at,coalesce(c.processed_events,0),coalesce(c.retries,0),c.last_error_at,coalesce(c.last_error,''),coalesce(c.error_stage,''),coalesce(c.stages,'{}'),coalesce(c.events_per_second,0),coalesce(c.completed_segments,0),coalesce(c.timeout_failures,0),coalesce(c.pause_reason,'')
 FROM discovery_pipeline_summary s LEFT JOIN LATERAL (SELECT * FROM discovery_consumer_runtime c WHERE c.lane=s.lane ORDER BY c.heartbeat_at DESC LIMIT 1) c ON true ORDER BY s.lane`)
	if err != nil {
		return PipelineStatus{}, err
	}
	defer rows.Close()
	out := PipelineStatus{Status: "ready", Lanes: []PipelineLane{}}
	for rows.Next() {
		var s PipelineLane
		var raw []byte
		if err = rows.Scan(&s.Lane, &s.PendingBatches, &s.EligibleBatches, &s.FailedBatches, &s.RemainingEvents, &s.OldestPendingAt, &s.LastProgressAt, &s.UpdatedAt, &s.HeartbeatAt, &s.StartedAt, &s.ProcessedEvents, &s.Retries, &s.LastErrorAt, &s.LastError, &s.ErrorStage, &raw, &s.EventsPerSecond, &s.CompletedSegments, &s.TimeoutFailures, &s.PauseReason); err != nil {
			return PipelineStatus{}, err
		}
		if err = json.Unmarshal(raw, &s.Stages); err != nil {
			return PipelineStatus{}, err
		}
		s.State = s.Status(time.Now())
		if s.State != "idle" && s.State != "processing" {
			out.Status = "delayed"
		}
		out.Lanes = append(out.Lanes, s)
	}
	if len(out.Lanes) == 0 {
		out.Status = "initializing"
	}
	if err = rows.Err(); err != nil {
		return PipelineStatus{}, err
	}
	rows.Close()
	consumers, err := r.pipelineConsumers(ctx)
	if err != nil {
		return PipelineStatus{}, err
	}
	out.Consumers = consumers
	for _, c := range consumers {
		if c.State != "running" {
			out.Status = "delayed"
		}
	}
	return out, nil
}

type StageStats struct {
	Calls      int64   `json:"calls"`
	Errors     int64   `json:"errors"`
	Seconds    float64 `json:"seconds"`
	MaxSeconds float64 `json:"max_seconds"`
}
type PipelineObserver struct {
	pauseReason                        string
	completedSegments, timeoutFailures int64
	lastFlush                          time.Time
	lastFlushedEvents                  int64
	mu                                 sync.Mutex
	started                            time.Time
	progress                           *time.Time
	processed, retries                 int64
	lastErrorAt                        *time.Time
	lastError, stage                   string
	stages                             map[string]StageStats
}

func newPipelineObserver() *PipelineObserver {
	return &PipelineObserver{started: time.Now().UTC(), stages: map[string]StageStats{}}
}

type observerKey struct{}

func WithPipelineObserver(ctx context.Context, o *PipelineObserver) context.Context {
	return context.WithValue(ctx, observerKey{}, o)
}
func ObserveStage(ctx context.Context, stage string, started time.Time, err error) {
	o, _ := ctx.Value(observerKey{}).(*PipelineObserver)
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.stages[stage]
	s.Calls++
	duration := time.Since(started).Seconds()
	s.Seconds += duration
	s.MaxSeconds = max(s.MaxSeconds, duration)
	if err != nil {
		s.Errors++
	}
	o.stages[stage] = s
}
func recordPipelineResult(ctx context.Context, n int, err error, stage string) {
	recordPipelineResultWithCompletion(ctx, n, err, stage, true)
}
func recordPipelineProgress(ctx context.Context, n int, segmentComplete bool) {
	recordPipelineResultWithCompletion(ctx, n, nil, "", segmentComplete)
}
func recordPipelineResultWithCompletion(ctx context.Context, n int, err error, stage string, segmentComplete bool) {
	o, _ := ctx.Value(observerKey{}).(*PipelineObserver)
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now().UTC()
	if err != nil {
		o.retries++
		if WorkErrorCode(err) == "deadline_exceeded" {
			o.timeoutFailures++
		}
		o.lastErrorAt = &now
		o.lastError = WorkErrorCode(err)
		o.stage = stage
		return
	}
	o.lastError = ""
	o.stage = ""
	if n > 0 {
		o.processed += int64(n)
		if segmentComplete {
			o.completedSegments++
		}
		o.progress = &now
	}
}
func (o *PipelineObserver) flush(ctx context.Context, db *sql.DB, id, lane, mode string) error {
	o.mu.Lock()
	sampleAt := time.Now().UTC()
	since := o.lastFlush
	if since.IsZero() {
		since = o.started
	}
	rate := float64(0)
	if elapsed := sampleAt.Sub(since).Seconds(); elapsed > 0 {
		rate = float64(o.processed-o.lastFlushedEvents) / elapsed
	}
	stages, _ := json.Marshal(o.stages)
	started, progress, processed, retries, lastErrorAt, lastError, stage := o.started, o.progress, o.processed, o.retries, o.lastErrorAt, o.lastError, o.stage
	segments, timeouts, pause := o.completedSegments, o.timeoutFailures, o.pauseReason
	o.mu.Unlock()
	_, err := db.ExecContext(ctx, `INSERT INTO discovery_consumer_runtime(consumer_id,lane,mode,started_at,heartbeat_at,last_progress_at,processed_events,retries,last_error_at,last_error,error_stage,stages,events_per_second,completed_segments,timeout_failures,pause_reason)
 VALUES($1,$2,$3,$4,now(),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(consumer_id) DO UPDATE SET mode=EXCLUDED.mode,started_at=EXCLUDED.started_at,heartbeat_at=EXCLUDED.heartbeat_at,last_progress_at=EXCLUDED.last_progress_at,processed_events=EXCLUDED.processed_events,retries=EXCLUDED.retries,last_error_at=EXCLUDED.last_error_at,last_error=EXCLUDED.last_error,error_stage=EXCLUDED.error_stage,stages=EXCLUDED.stages,events_per_second=EXCLUDED.events_per_second,completed_segments=EXCLUDED.completed_segments,timeout_failures=EXCLUDED.timeout_failures,pause_reason=EXCLUDED.pause_reason`, id, lane, mode, started, progress, processed, retries, lastErrorAt, lastError, stage, stages, rate, segments, timeouts, pause)
	if err == nil {
		o.mu.Lock()
		o.lastFlush = sampleAt
		o.lastFlushedEvents = processed
		o.mu.Unlock()
	}
	return err
}
func (r Repository) RefreshPipelineSummary(ctx context.Context) error {
	_, err := r.DB.ExecContext(ctx, `INSERT INTO discovery_pipeline_summary(lane,pending_batches,eligible_batches,failed_batches,remaining_events,oldest_pending_at,last_progress_at,updated_at)
 SELECT l.lane,count(w.batch_id),count(w.batch_id) FILTER(WHERE w.next_attempt_at<=now() AND w.lease_until<=now() AND (b.source_kind='discovery-v2' OR b.status='committed')),
 count(w.batch_id) FILTER(WHERE w.error<>''),coalesce(sum(greatest(coalesce(w.selected_event_count,b.event_count)-w.processed_offset,0)),0),min(w.created_at),max(w.last_progress_at),now()
 FROM (VALUES('realtime'),('backfill')) l(lane) LEFT JOIN discovery_batch_work w ON w.lane=l.lane AND NOT w.completed LEFT JOIN ingest_batches b USING(batch_id) GROUP BY l.lane
 ON CONFLICT(lane) DO UPDATE SET pending_batches=EXCLUDED.pending_batches,eligible_batches=EXCLUDED.eligible_batches,failed_batches=EXCLUDED.failed_batches,remaining_events=EXCLUDED.remaining_events,oldest_pending_at=EXCLUDED.oldest_pending_at,last_progress_at=EXCLUDED.last_progress_at,updated_at=EXCLUDED.updated_at`)
	return err
}

type archiveAdmissionKey struct{}

func WithArchiveAdmission(ctx context.Context, at time.Time) context.Context {
	return context.WithValue(ctx, archiveAdmissionKey{}, at)
}
func ArchiveAdmission(ctx context.Context) time.Time {
	at, _ := ctx.Value(archiveAdmissionKey{}).(time.Time)
	if at.IsZero() {
		return time.Now().UTC()
	}
	return at
}

func (o *PipelineObserver) SetPause(reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pauseReason = reason
}
func NewPipelineObserver() *PipelineObserver { return newPipelineObserver() }
func (o *PipelineObserver) Flush(ctx context.Context, db *sql.DB, id, lane, mode string) error {
	return o.flush(ctx, db, id, lane, mode)
}
func RecordPipelineResult(ctx context.Context, n int, err error, stage string) {
	recordPipelineResult(ctx, n, err, stage)
}

type PipelineConsumer struct {
	ID              string     `json:"id"`
	Role            string     `json:"role"`
	State           string     `json:"status"`
	HeartbeatAt     time.Time  `json:"heartbeat_at"`
	LastProgressAt  *time.Time `json:"last_progress_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	LastErrorAt     *time.Time `json:"last_error_at,omitempty"`
	ProcessedEvents int64      `json:"processed_events"`
}

func (r Repository) pipelineConsumers(ctx context.Context) ([]PipelineConsumer, error) {
	rows, err := r.DB.QueryContext(ctx, `SELECT consumer_id,lane,heartbeat_at,last_progress_at,last_error,processed_events,last_error_at FROM discovery_consumer_runtime WHERE lane='dhcp' ORDER BY consumer_id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PipelineConsumer{}
	for rows.Next() {
		var c PipelineConsumer
		if err = rows.Scan(&c.ID, &c.Role, &c.HeartbeatAt, &c.LastProgressAt, &c.LastError, &c.ProcessedEvents, &c.LastErrorAt); err != nil {
			return nil, err
		}
		c.State = "running"
		if c.LastError != "" && c.LastErrorAt != nil {
			c.State = "retrying"
		}
		if time.Since(c.HeartbeatAt) > 15*time.Second {
			c.State = "interrupted"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
