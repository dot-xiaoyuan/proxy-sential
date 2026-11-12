package eventbus

import (
	"context"
	"errors"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Record is the small transport shape used by the shadow publisher and the
// probe. It deliberately does not expose franz-go types outside this package.
type Record struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers map[string]string
}

// Producer is the write side of the event bus. Produce is asynchronous: the
// callback is the authoritative delivery result. A returned error means the
// record was not accepted into the local producer buffer.
type Producer interface {
	Produce(ctx context.Context, record Record, done func(error)) error
	Flush(ctx context.Context) error
	Close()
}

type KafkaProducer struct {
	client *kgo.Client
}

func NewKafkaProducer(cfg Config) (*KafkaProducer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("event bus producer requires brokers")
	}
	if cfg.Queue < 1 {
		return nil, errors.New("event bus producer requires a positive queue")
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		// Idempotent production is the franz-go default; do not disable it.
		kgo.ProducerBatchCompression(kgo.ZstdCompression()),
		kgo.ProducerLinger(cfg.Linger),
		kgo.ProducerBatchMaxBytes(1 << 20),
		kgo.MaxBufferedRecords(cfg.Queue),
		kgo.RecordDeliveryTimeout(10 * time.Second),
		kgo.RecordRetries(5),
	}
	// The best-effort shadow retains its historical auto-create behavior.
	// A durable canary must be pointed at a pre-created, inspected topic.
	if cfg.ReliableSource == "" {
		opts = append(opts, kgo.AllowAutoTopicCreation())
	}
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &KafkaProducer{client: client}, nil
}

func (p *KafkaProducer) Produce(ctx context.Context, record Record, done func(error)) error {
	if p == nil || p.client == nil {
		return errors.New("event bus producer is closed")
	}
	if record.Topic == "" || len(record.Key) == 0 || len(record.Value) == 0 {
		return errors.New("event bus producer record is incomplete")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	message := &kgo.Record{Topic: record.Topic, Key: record.Key, Value: record.Value}
	for key, value := range record.Headers {
		message.Headers = append(message.Headers, kgo.RecordHeader{Key: key, Value: []byte(value)})
	}
	p.client.Produce(ctx, message, func(_ *kgo.Record, err error) {
		if done != nil {
			done(err)
		}
	})
	return nil
}

func (p *KafkaProducer) Flush(ctx context.Context) error {
	if p == nil || p.client == nil {
		return nil
	}
	return p.client.Flush(ctx)
}

func (p *KafkaProducer) Close() {
	if p == nil || p.client == nil {
		return
	}
	p.client.Close()
	p.client = nil
}
