package eventbus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type StatsSnapshot struct {
	Enabled        bool     `json:"enabled"`
	Topic          string   `json:"topic,omitempty"`
	Brokers        []string `json:"brokers,omitempty"`
	Published      int64    `json:"published"`
	Failed         int64    `json:"failed"`
	Dropped        int64    `json:"dropped"`
	Segments       int64    `json:"segments"`
	QueueDepth     int64    `json:"queue_depth"`
	LastSuccess    string   `json:"last_success,omitempty"`
	LastError      string   `json:"last_error,omitempty"`
	LastErrorAt    string   `json:"last_error_at,omitempty"`
	DisabledReason string   `json:"disabled_reason,omitempty"`
	UpdatedAt      string   `json:"updated_at"`
}

type Stats struct {
	mu             sync.Mutex
	enabled        bool
	topic          string
	brokers        []string
	disabledReason string
	published      atomic.Int64
	failed         atomic.Int64
	dropped        atomic.Int64
	segments       atomic.Int64
	queueDepth     atomic.Int64
	lastSuccess    time.Time
	lastError      time.Time
	lastErrorText  string
	path           string
}

func NewStats(cfg Config) *Stats {
	return &Stats{
		enabled: cfg.Enabled,
		topic:   cfg.DiscoveryTopic,
		brokers: append([]string(nil), cfg.Brokers...),
		path:    cfg.StatsPath,
	}
}

func (s *Stats) RecordSegment() {
	if s != nil {
		s.segments.Add(1)
	}
}

func (s *Stats) RecordPublished() {
	if s == nil {
		return
	}
	s.published.Add(1)
	s.mu.Lock()
	s.lastSuccess = time.Now().UTC()
	s.mu.Unlock()
}

func (s *Stats) RecordFailed(err error) {
	if s == nil {
		return
	}
	s.failed.Add(1)
	s.mu.Lock()
	s.lastError = time.Now().UTC()
	if err != nil {
		s.lastErrorText = err.Error()
	}
	s.mu.Unlock()
}

func (s *Stats) RecordDropped(n int64) {
	if s != nil && n > 0 {
		s.dropped.Add(n)
	}
}

func (s *Stats) SetQueueDepth(n int) {
	if s != nil {
		s.queueDepth.Store(int64(n))
	}
}

func (s *Stats) Snapshot() StatsSnapshot {
	if s == nil {
		return StatsSnapshot{UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	s.mu.Lock()
	lastSuccess, lastError, lastErrorText := s.lastSuccess, s.lastError, s.lastErrorText
	s.mu.Unlock()
	out := StatsSnapshot{
		Enabled:        s.enabled,
		Topic:          s.topic,
		Brokers:        append([]string(nil), s.brokers...),
		Published:      s.published.Load(),
		Failed:         s.failed.Load(),
		Dropped:        s.dropped.Load(),
		Segments:       s.segments.Load(),
		QueueDepth:     s.queueDepth.Load(),
		LastError:      lastErrorText,
		DisabledReason: s.disabledReason,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	if !lastSuccess.IsZero() {
		out.LastSuccess = lastSuccess.Format(time.RFC3339Nano)
	}
	if !lastError.IsZero() {
		out.LastErrorAt = lastError.Format(time.RFC3339Nano)
	}
	return out
}

func (s *Stats) Persist() error {
	if s == nil || s.path == "" {
		return nil
	}
	return writeStats(s.path, s.Snapshot())
}

// WriteDisabledStats records why the optional shadow publisher did not start.
// It is best effort and must never block capture.
func WriteDisabledStats(statsDir string, reason error) {
	if statsDir == "" {
		return
	}
	text := "disabled"
	if reason != nil {
		text = reason.Error()
	}
	stats := &Stats{
		enabled:        false,
		disabledReason: text,
		path:           filepath.Join(statsDir, "eventbus.stats"),
	}
	_ = stats.Persist()
}

func writeStats(path string, snapshot StatsSnapshot) error {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".eventbus-stats-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("replace event bus stats: %w", err)
	}
	return nil
}
