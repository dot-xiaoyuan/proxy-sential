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
	mu     sync.Mutex
	since  time.Time
	stages map[string]passiveStageMetrics
	queues map[string]passiveQueueMetrics
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
type passiveMetricsSnapshot struct {
	Kind        string                         `json:"kind"`
	WindowStart time.Time                      `json:"window_start"`
	At          time.Time                      `json:"at"`
	Stages      map[string]passiveStageMetrics `json:"stages"`
	Queues      map[string]passiveQueueMetrics `json:"queues"`
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
	case streamlog.StageLoad, streamlog.StagePreflight, streamlog.StageBeginAttempt, streamlog.StageWrite, streamlog.StageReconcile, streamlog.StageAck, streamlog.StageFinalize, streamlog.StageRelease, "enqueue", "append_commit":
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
	snapshot := passiveMetricsSnapshot{Kind: kind, WindowStart: m.since, At: at.UTC(), Stages: m.stages, Queues: m.queues}
	m.since = at.UTC()
	m.stages = make(map[string]passiveStageMetrics)
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
