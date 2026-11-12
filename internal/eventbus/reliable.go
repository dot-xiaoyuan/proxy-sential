package eventbus

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"proxy-sentinel/internal/streamlog"
)

// ReliablePublisher waits for broker delivery callbacks. Its caller owns the
// durable segment and records the eventbus lane ACK only after Publish returns.
// An ambiguous attempt republishes stable event IDs; broker idempotence is not
// an end-to-end exactly-once guarantee.
type ReliablePublisher struct {
	cfg       Config
	producer  Producer
	keyFunc   PartitionKeyFunc
	stats     *Stats
	closeOnce sync.Once
	closeErr  error
}

func NewReliablePublisher(cfg Config, producer Producer, keyFunc PartitionKeyFunc) *ReliablePublisher {
	return &ReliablePublisher{cfg: cfg, producer: producer, keyFunc: keyFunc, stats: NewStats(cfg)}
}

func (p *ReliablePublisher) Preflight(id string, segment streamlog.Segment) error {
	_, err := p.records(id, segment)
	return err
}

func (p *ReliablePublisher) records(id string, segment streamlog.Segment) ([]Record, error) {
	if p == nil || p.producer == nil || p.keyFunc == nil {
		return nil, errors.New("reliable event bus publisher is unavailable")
	}
	if !segment.EventBusRequired || len(segment.Events) == 0 {
		return nil, errors.New("segment is not marked for reliable event bus delivery")
	}
	meta := segment
	meta.Events = nil
	meta.Raw = nil
	records := make([]Record, 0, len(segment.Events))
	for _, event := range segment.Events {
		key, source := p.keyFunc(event)
		if key == "" {
			return nil, fmt.Errorf("event %s has no stable partition key", event.EventID)
		}
		envelope, err := NewDiscoveryEnvelope(id, meta, event, key)
		if err != nil {
			return nil, err
		}
		raw, err := envelope.Marshal()
		if err != nil {
			return nil, err
		}
		if len(raw) > p.cfg.MaxRecordBytes {
			return nil, fmt.Errorf("event bus record exceeds %d bytes", p.cfg.MaxRecordBytes)
		}
		records = append(records, Record{
			Topic: p.cfg.DiscoveryTopic,
			Key:   envelope.Key(),
			Value: raw,
			Headers: map[string]string{
				"schema_version":       fmt.Sprintf("%d", envelope.SchemaVersion),
				"partition_key_source": source,
				"event_type":           envelope.EventType,
			},
		})
	}
	return records, nil
}

// Publish sends bounded windows and waits for every callback in each window.
// It never discards records on a full producer queue; the caller's journal and
// bounded capture backlog provide backpressure until the broker recovers.
func (p *ReliablePublisher) Publish(ctx context.Context, id string, segment streamlog.Segment) error {
	if ctx == nil {
		ctx = context.Background()
	}
	records, err := p.records(id, segment)
	if err != nil {
		return err
	}
	p.stats.RecordSegment()
	window := p.cfg.Queue
	if window > 64 {
		window = 64
	}
	if window < 1 {
		return errors.New("reliable event bus queue limit must be positive")
	}
	for start := 0; start < len(records); start += window {
		end := start + window
		if end > len(records) {
			end = len(records)
		}
		callbacks := make(chan error, end-start)
		pending := 0
		var sendErr error
		for _, record := range records[start:end] {
			if err := ctx.Err(); err != nil {
				sendErr = err
				break
			}
			if err := p.producer.Produce(ctx, record, func(err error) { callbacks <- err }); err != nil {
				sendErr = err
				break
			}
			pending++
		}
		for pending > 0 {
			select {
			case deliveryErr := <-callbacks:
				pending--
				if deliveryErr != nil {
					p.stats.RecordFailed(deliveryErr)
					sendErr = errors.Join(sendErr, deliveryErr)
				} else {
					p.stats.RecordPublished()
				}
			case <-ctx.Done():
				p.stats.RecordFailed(ctx.Err())
				return errors.Join(sendErr, ctx.Err())
			}
		}
		if sendErr != nil {
			p.stats.RecordFailed(sendErr)
			return sendErr
		}
	}
	return nil
}

func (p *ReliablePublisher) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.closeOnce.Do(func() {
		p.closeErr = p.producer.Flush(ctx)
		p.producer.Close()
		p.closeErr = errors.Join(p.closeErr, p.stats.Persist())
	})
	return p.closeErr
}
