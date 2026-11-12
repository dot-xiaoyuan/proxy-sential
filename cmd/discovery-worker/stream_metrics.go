package main

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/streamlog"
)

// Only fixed lane/stage names enter these maps. No segment IDs, errors, samples
// or event data are retained. Updating metrics never performs disk/network I/O.
type passiveStreamMetrics struct {
	mu               sync.Mutex
	since            time.Time
	stages           map[string]passiveStageMetrics
	queues           map[string]passiveQueueMetrics
	projectionWrites map[string]passiveProjectionWriteMetrics
	sinkAcks         map[string]passiveSinkAckMetrics
	captureAccepted  map[string]passiveCaptureAcceptedMetrics
	captureBatches   passiveCaptureBatchMetrics
	buffer           *passiveDurableBuffer
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
type passiveProjectionWriteMetrics struct {
	Segments    uint64 `json:"segments"`
	Events      uint64 `json:"events"`
	FreshEvents uint64 `json:"fresh_events"`
	FactRows    uint64 `json:"pg_fact_rows"`
	StateRows   uint64 `json:"pg_state_rows"`
}
type passiveSinkAckMetrics struct {
	BodySegments   uint64 `json:"body_segments"`
	BodyEvents     uint64 `json:"body_events"`
	SearchSegments uint64 `json:"search_segments"`
	SearchEvents   uint64 `json:"search_events"`
	BusSegments    uint64 `json:"eventbus_segments"`
	BusEvents      uint64 `json:"eventbus_events"`
}
type passiveCaptureAcceptedMetrics struct {
	Segments    uint64 `json:"segments"`
	Events      uint64 `json:"events"`
	SourceBytes uint64 `json:"source_bytes"`
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
	Kind             string                                   `json:"kind"`
	WindowStart      time.Time                                `json:"window_start"`
	At               time.Time                                `json:"at"`
	Stages           map[string]passiveStageMetrics           `json:"stages"`
	Queues           map[string]passiveQueueMetrics           `json:"queues"`
	ProjectionWrites map[string]passiveProjectionWriteMetrics `json:"projection_writes"`
	SinkAcks         map[string]passiveSinkAckMetrics         `json:"sink_acks"`
	CaptureAccepted  map[string]passiveCaptureAcceptedMetrics `json:"capture_accepted"`
	CaptureBatches   passiveCaptureBatchMetrics               `json:"capture_batches"`
	DurableBacklog   *passiveBacklogSnapshot                  `json:"durable_backlog,omitempty"`
}

func newPassiveStreamMetrics() *passiveStreamMetrics {
	return &passiveStreamMetrics{since: time.Now().UTC(), stages: make(map[string]passiveStageMetrics), queues: make(map[string]passiveQueueMetrics), projectionWrites: make(map[string]passiveProjectionWriteMetrics), sinkAcks: make(map[string]passiveSinkAckMetrics), captureAccepted: make(map[string]passiveCaptureAcceptedMetrics)}
}

// This counts standard events durably accepted at the capture boundary. For
// passive packets, source bytes are serialized standard-event cursor bytes;
// packet payloads are not retained and cannot be counted from this callback.
func (m *passiveStreamMetrics) observeCapture(segment streamlog.Segment) {
	if segment.Source == "" || segment.Epoch == "" || segment.EndOffset < segment.StartOffset || segment.StartOffset < 0 {
		return
	}
	key := segment.Source + "/" + segment.Epoch
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.captureAccepted[key]
	current.Segments++
	current.Events += uint64(len(segment.Events))
	current.SourceBytes += uint64(segment.EndOffset - segment.StartOffset)
	m.captureAccepted[key] = current
}

func (m *passiveStreamMetrics) observeAck(lane streamlog.Lane, segment streamlog.Segment) {
	if segment.Source == "" || segment.Epoch == "" || (lane != streamlog.Archive && lane != streamlog.Search && lane != streamlog.EventBus) {
		return
	}
	key := segment.Source + "/" + segment.Epoch
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.sinkAcks[key]
	if lane == streamlog.Archive {
		current.BodySegments++
		current.BodyEvents += uint64(len(segment.Events))
	} else if lane == streamlog.Search {
		current.SearchSegments++
		current.SearchEvents += uint64(len(segment.Events))
	} else {
		current.BusSegments++
		current.BusEvents += uint64(len(segment.Events))
	}
	m.sinkAcks[key] = current
}

func (m *passiveStreamMetrics) observeProjectionWrite(value discovery.StreamProjectionWriteStats) {
	if value.Source == "" || value.Epoch == "" || value.Events < 0 || value.FreshEvents < 0 || value.FactRows < 0 || value.StateRows < 0 {
		return
	}
	key := value.Source + "/" + value.Epoch
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.projectionWrites[key]
	current.Segments++
	current.Events += uint64(value.Events)
	current.FreshEvents += uint64(value.FreshEvents)
	current.FactRows += uint64(value.FactRows)
	current.StateRows += uint64(value.StateRows)
	m.projectionWrites[key] = current
}

func (m *passiveStreamMetrics) observe(lane streamlog.Lane, stage streamlog.ProcessorStage, elapsed time.Duration, err error) {
	switch lane {
	case streamlog.Archive, streamlog.Search, streamlog.Projection, streamlog.RiskFeatures, streamlog.EventBus, "", "capture":
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
	case "archive", "search", "projection", "eventbus", "finalizer":
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
	snapshot := passiveMetricsSnapshot{Kind: kind, WindowStart: m.since, At: at.UTC(), Stages: m.stages, Queues: m.queues, ProjectionWrites: m.projectionWrites, SinkAcks: m.sinkAcks, CaptureAccepted: m.captureAccepted, CaptureBatches: m.captureBatches}
	if m.buffer != nil {
		backlog := m.buffer.snapshot()
		snapshot.DurableBacklog = &backlog
	}
	m.since = at.UTC()
	m.stages = make(map[string]passiveStageMetrics)
	m.projectionWrites = make(map[string]passiveProjectionWriteMetrics)
	m.sinkAcks = make(map[string]passiveSinkAckMetrics)
	m.captureAccepted = make(map[string]passiveCaptureAcceptedMetrics)
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
