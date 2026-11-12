package eventbus

import (
	"context"
	"errors"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestReliablePublisherWaitsForEveryBrokerCallback(t *testing.T) {
	cfg := testShadowConfig(t, 2)
	producer := &controlledProducer{callbacks: make(chan func(error), 2)}
	publisher := NewReliablePublisher(cfg, producer, func(event normalized.Event) (string, string) { return event.EventID, "event_id" })
	at := time.Now().UTC()
	segment := testSegment(at, testEvent("event-a", at), testEvent("event-b", at))
	segment.EventBusRequired = true
	done := make(chan error, 1)
	go func() { done <- publisher.Publish(context.Background(), "segment-a", segment) }()
	first := <-producer.callbacks
	select {
	case err := <-done:
		t.Fatalf("returned before first ACK: %v", err)
	default:
	}
	first(nil)
	second := <-producer.callbacks
	select {
	case err := <-done:
		t.Fatalf("returned before second ACK: %v", err)
	default:
	}
	second(nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if producer.count != 2 {
		t.Fatalf("produced %d records", producer.count)
	}
}

func TestReliablePublisherRejectsInvalidSegmentBeforeAnySend(t *testing.T) {
	cfg := testShadowConfig(t, 2)
	producer := &controlledProducer{callbacks: make(chan func(error), 2)}
	publisher := NewReliablePublisher(cfg, producer, func(event normalized.Event) (string, string) {
		if event.EventID == "bad" {
			return "", ""
		}
		return event.EventID, "event_id"
	})
	at := time.Now().UTC()
	segment := testSegment(at, testEvent("good", at), testEvent("bad", at))
	segment.EventBusRequired = true
	err := publisher.Publish(context.Background(), "segment-a", segment)
	if err == nil || producer.count != 0 {
		t.Fatalf("partial publish on local error: err=%v count=%d", err, producer.count)
	}
}

func TestReliablePublisherLeavesFailedCallbackForJournalRetry(t *testing.T) {
	cfg := testShadowConfig(t, 2)
	producer := &controlledProducer{callbacks: make(chan func(error), 2)}
	publisher := NewReliablePublisher(cfg, producer, func(event normalized.Event) (string, string) { return event.EventID, "event_id" })
	at := time.Now().UTC()
	done := make(chan error, 1)
	segment := testSegment(at, testEvent("event-a", at))
	segment.EventBusRequired = true
	go func() { done <- publisher.Publish(context.Background(), "segment-a", segment) }()
	(<-producer.callbacks)(errors.New("broker unavailable"))
	if err := <-done; err == nil {
		t.Fatal("failed callback reported success")
	}
}

type controlledProducer struct {
	callbacks chan func(error)
	count     int
}

func (p *controlledProducer) Produce(ctx context.Context, _ Record, done func(error)) error {
	p.count++
	select {
	case p.callbacks <- done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*controlledProducer) Flush(context.Context) error { return nil }
func (*controlledProducer) Close()                      {}
