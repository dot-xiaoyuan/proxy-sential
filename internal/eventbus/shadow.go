package eventbus

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

// PartitionKeyFunc maps a standard event to a stable Kafka key. Discovery owns
// the key rules; the event bus only needs the resulting string.
type PartitionKeyFunc func(normalized.Event) (key string, source string)

type eventJob struct {
	id      string
	segment streamlog.Segment
	event   normalized.Event
}

// Shadow publishes new discovery events to Kafka without participating in the
// read path. It is deliberately best-effort: a broker problem must not stop
// capture or the existing journal lanes.
type Shadow struct {
	cfg      Config
	producer Producer
	keyFunc  PartitionKeyFunc
	stats    *Stats
	queue    chan eventJob
	done     chan struct{}

	mu       sync.RWMutex
	closed   bool
	closeOne sync.Once
	finalOne sync.Once
	finalErr error

	lastLog atomic.Int64
}

func NewShadowFromEnv(ctx context.Context, node, statsDir string, keyFunc PartitionKeyFunc) (*Shadow, error) {
	cfg, err := ConfigFromEnv(node, statsDir)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	producer, err := NewKafkaProducer(cfg)
	if err != nil {
		return nil, err
	}
	return NewShadow(cfg, producer, keyFunc), nil
}

func NewShadow(cfg Config, producer Producer, keyFunc PartitionKeyFunc) *Shadow {
	if keyFunc == nil {
		keyFunc = func(event normalized.Event) (string, string) {
			if event.EventID == "" {
				return "", ""
			}
			return event.EventID, "event"
		}
	}
	shadow := &Shadow{
		cfg:      cfg,
		producer: producer,
		keyFunc:  keyFunc,
		stats:    NewStats(cfg),
		queue:    make(chan eventJob, cfg.Queue),
		done:     make(chan struct{}),
	}
	go shadow.run()
	return shadow
}

// Publish enqueues every event in the captured segment. It never blocks on the
// event bus; a full queue is counted and the existing journal lanes continue.
func (s *Shadow) Publish(id string, segment streamlog.Segment) {
	if s == nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	meta := segment
	meta.Events = nil
	meta.Raw = nil
	for _, event := range segment.Events {
		job := eventJob{id: id, segment: meta, event: event}
		select {
		case s.queue <- job:
		default:
			s.stats.RecordDropped(1)
		}
	}
	s.stats.RecordSegment()
	s.stats.SetQueueDepth(len(s.queue))
}

func (s *Shadow) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.closeOne.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
	})
	s.finalOne.Do(func() {
		select {
		case <-s.done:
		case <-ctx.Done():
			s.finalErr = ctx.Err()
		}
		if s.finalErr == nil {
			if err := s.producer.Flush(ctx); err != nil {
				s.finalErr = err
				s.stats.RecordFailed(err)
			}
		}
		s.producer.Close()
		s.stats.SetQueueDepth(0)
		if err := s.stats.Persist(); err != nil && s.finalErr == nil {
			s.finalErr = err
		}
	})
	return s.finalErr
}

func (s *Shadow) run() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case job, ok := <-s.queue:
			if !ok {
				s.stats.SetQueueDepth(0)
				_ = s.stats.Persist()
				close(s.done)
				return
			}
			s.publish(job)
		case <-ticker.C:
			s.stats.SetQueueDepth(len(s.queue))
			_ = s.stats.Persist()
		}
	}
}

func (s *Shadow) publish(job eventJob) {
	key, source := s.keyFunc(job.event)
	if key == "" {
		s.fail(job, errors.New("event has no stable partition key"))
		return
	}
	envelope, err := NewDiscoveryEnvelope(job.id, job.segment, job.event, key)
	if err != nil {
		s.fail(job, err)
		return
	}
	raw, err := envelope.Marshal()
	if err != nil {
		s.fail(job, err)
		return
	}
	if len(raw) > s.cfg.MaxRecordBytes {
		s.fail(job, fmt.Errorf("event bus record exceeds %d bytes", s.cfg.MaxRecordBytes))
		return
	}
	headers := map[string]string{
		"schema_version":       fmt.Sprintf("%d", envelope.SchemaVersion),
		"partition_key_source": source,
		"event_type":           envelope.EventType,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = s.producer.Produce(ctx, Record{
		Topic:   s.cfg.DiscoveryTopic,
		Key:     envelope.Key(),
		Value:   raw,
		Headers: headers,
	}, func(deliveryErr error) {
		if deliveryErr != nil {
			s.stats.RecordFailed(deliveryErr)
			s.report("delivery failed: " + deliveryErr.Error())
			return
		}
		s.stats.RecordPublished()
	})
	if err != nil {
		s.fail(job, err)
	}
}

func (s *Shadow) fail(job eventJob, err error) {
	s.stats.RecordFailed(err)
	s.report(fmt.Sprintf("event %s: %v", job.event.EventID, err))
}

func (s *Shadow) report(message string) {
	now := time.Now().UnixNano()
	previous := s.lastLog.Load()
	if previous != 0 && now-previous < int64(30*time.Second) {
		return
	}
	if s.lastLog.CompareAndSwap(previous, now) {
		log.Printf("event-bus shadow: %s", message)
	}
}
