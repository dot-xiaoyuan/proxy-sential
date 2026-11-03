package main

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// Only fixed lane/stage names enter these maps. No segment IDs, errors, samples
// or event data are retained. Updating metrics never performs disk/network I/O.
type passiveStreamMetrics struct {
	mu             sync.Mutex
	since          time.Time
	stages         map[string]passiveStageMetrics
	queues         map[string]passiveQueueMetrics
	captureBatches passiveCaptureBatchMetrics
	buffer         *passiveDurableBuffer
}
type passiveStageMetrics struct {
	Count    uint64  `json:"count"`
	Failures uint64  `json:"failures"`
	TotalMS  float64 `json:"total_ms"`
	MaxMS    float64 `json:"max_ms"`
}
type passiveQueueMetrics struct {
	Depth      int `json:"depth"`
	Capacity   int `json:"capacity"`
	SampledMax int `json:"sampled_max"`
}

// Cumulative fixed buckets show whether the writer is accepting small or
// nearly full segments. They contain no source identity or event content.
type passiveCaptureBatchMetrics struct {
	Count          uint64 `json:"count"`
	Events         uint64 `json:"events"`
	SourceBytes    uint64 `json:"source_bytes"`
	MaxEvents      int    `json:"max_events"`
	MaxSourceBytes int64  `json:"max_source_bytes"`
	EventsLE250    uint64 `json:"events_le_250"`
	EventsLE500    uint64 `json:"events_le_500"`
	EventsLE750    uint64 `json:"events_le_750"`
	EventsLE1000   uint64 `json:"events_le_1000"`
	BytesLE256KiB  uint64 `json:"bytes_le_256_kib"`
	BytesLE512KiB  uint64 `json:"bytes_le_512_kib"`
	BytesLE1MiB    uint64 `json:"bytes_le_1_mib"`
}
type passiveMetricsSnapshot struct {
	Kind           string                         `json:"kind"`
	WindowStart    time.Time                      `json:"window_start"`
	At             time.Time                      `json:"at"`
	Stages         map[string]passiveStageMetrics `json:"stages"`
	Queues         map[string]passiveQueueMetrics `json:"queues"`
	CaptureBatches passiveCaptureBatchMetrics     `json:"capture_batches"`
	DurableBacklog *passiveBacklogSnapshot        `json:"durable_backlog,omitempty"`
}

func newPassiveStreamMetrics() *passiveStreamMetrics {
	return &passiveStreamMetrics{since: time.Now().UTC(), stages: make(map[string]passiveStageMetrics), queues: make(map[string]passiveQueueMetrics)}
}

func (m *passiveStreamMetrics) observe(lane streamlog.Lane, stage streamlog.ProcessorStage, elapsed time.Duration, err error) {
	switch lane {
	case streamlog.Archive, streamlog.Search, streamlog.Projection, streamlog.RiskFeatures, "", "capture":
	default:
		return
	}
	switch stage {
	case streamlog.StageLoad, streamlog.StagePreflight, streamlog.StageBeginAttempt, streamlog.StageWrite, streamlog.StageReconcile, streamlog.StageAck, streamlog.StageFinalize, streamlog.StageRelease, "enqueue", "append_commit", "append", "commit":
	default:
		return
	}
	name := string(lane)
	if name == "" {
		name = "finalizer"
	}
	key := name + "." + string(stage)
	ms := float64(elapsed) / float64(time.Millisecond)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observeStageLocked(key, ms, err)
}

func (m *passiveStreamMetrics) observeStageLocked(key string, ms float64, err error) {
	value := m.stages[key]
	value.Count++
	if err != nil {
		value.Failures++
	}
	value.TotalMS += ms
	if ms > value.MaxMS {
		value.MaxMS = ms
	}
	m.stages[key] = value
}

func (m *passiveStreamMetrics) observeJournal(phases streamlog.PassiveJournalPhases, eventCount int, sourceBytes int64, err error) {
	if !phases.AppendAttempted {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	appendErr := err
	if phases.CommitAttempted {
		appendErr = nil
	}
	m.observeStageLocked("capture.append", float64(phases.AppendDuration)/float64(time.Millisecond), appendErr)
	if phases.CommitAttempted {
		m.observeStageLocked("capture.commit", float64(phases.CommitDuration)/float64(time.Millisecond), err)
		for _, phase := range [...]struct {
			name     string
			duration time.Duration
		}{
			{"capture.commit.lock", phases.CommitLockDuration},
			{"capture.commit.load_verify", phases.CommitLoadDuration},
			{"capture.commit.ack", phases.CommitAckDuration},
			{"capture.commit.state", phases.CommitStateDuration},
			{"capture.commit.cursor", phases.CommitCursorDuration},
		} {
			if phase.duration > 0 {
				m.observeStageLocked(phase.name, float64(phase.duration)/float64(time.Millisecond), nil)
			}
		}
	}
	b := &m.captureBatches
	b.Count++
	if eventCount > 0 {
		b.Events += uint64(eventCount)
	}
	if sourceBytes > 0 {
		b.SourceBytes += uint64(sourceBytes)
	}
	if eventCount > b.MaxEvents {
		b.MaxEvents = eventCount
	}
	if sourceBytes > b.MaxSourceBytes {
		b.MaxSourceBytes = sourceBytes
	}
	if eventCount <= 250 {
		b.EventsLE250++
	}
	if eventCount <= 500 {
		b.EventsLE500++
	}
	if eventCount <= 750 {
		b.EventsLE750++
	}
	if eventCount <= 1000 {
		b.EventsLE1000++
	}
	if sourceBytes <= 256<<10 {
		b.BytesLE256KiB++
	}
	if sourceBytes <= 512<<10 {
		b.BytesLE512KiB++
	}
	if sourceBytes <= 1<<20 {
		b.BytesLE1MiB++
	}
}

func (m *passiveStreamMetrics) queue(name string, depth, capacity int) {
	switch name {
	case "archive", "search", "projection", "finalizer":
	default:
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value := m.queues[name]
	value.Depth = depth
	value.Capacity = capacity
	if depth > value.SampledMax {
		value.SampledMax = depth
	}
	m.queues[name] = value
}

func (m *passiveStreamMetrics) snapshot(kind string, at time.Time) passiveMetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := passiveMetricsSnapshot{Kind: kind, WindowStart: m.since, At: at.UTC(), Stages: m.stages, Queues: m.queues, CaptureBatches: m.captureBatches}
	if m.buffer != nil {
		backlog := m.buffer.snapshot()
		snapshot.DurableBacklog = &backlog
	}
	m.since = at.UTC()
	m.stages = make(map[string]passiveStageMetrics)
	m.captureBatches = passiveCaptureBatchMetrics{}
	m.queues = make(map[string]passiveQueueMetrics, len(snapshot.Queues))
	for name, value := range snapshot.Queues {
		value.SampledMax = value.Depth
		m.queues[name] = value
	}
	return snapshot
}

// Called only by the independent reporting goroutine, outside capture/lanes.
func (m *passiveStreamMetrics) report(kind string) {
	raw, err := json.Marshal(m.snapshot(kind, time.Now()))
	if err == nil {
		log.Printf("passive stream metrics %s", raw)
	}
}

func enqueuePassiveLane(ctx context.Context, queue chan<- string, id string, lane streamlog.Lane, m *passiveStreamMetrics) (err error) {
	started := time.Now()
	defer func() {
		m.observe(lane, "enqueue", time.Since(started), err)
		m.queue(string(lane), len(queue), cap(queue))
	}()
	select {
	case queue <- id:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
