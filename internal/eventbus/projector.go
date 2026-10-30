package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Receipt is the minimum immutable row needed to prove that one Kafka record
// reached the shadow sink. It intentionally does not contain a second copy of
// the normalized event outside Envelope.
type Receipt struct {
	EventID     string
	DeviceKey   string
	ObservedAt  time.Time
	AcceptedAt  time.Time
	SegmentID   string
	ContentHash string
	SensorID    string
	ScopeID     string
	Source      string
	SourcePath  string
	Partition   int32
	Offset      int64
	Envelope    []byte
	ConsumedAt  time.Time
}

// ReceiptSink is the Phase 2 shadow boundary. A sink must make repeated writes
// of the same event idempotent; the projector commits Kafka offsets only after
// the sink returns success.
type ReceiptSink interface {
	WriteReceipts(ctx context.Context, receipts []Receipt) error
}

// ProjectorOptions configures a bounded, at-least-once Kafka consumer whose
// only job is to write shadow receipts. It has no access to the discovery read
// path or to the legacy projector.
type ProjectorOptions struct {
	Brokers       []string
	Topic         string
	Group         string
	ClientID      string
	BatchSize     int
	FetchMaxBytes int
	FlushInterval time.Duration
}

func (o ProjectorOptions) validate() error {
	if len(o.Brokers) == 0 {
		return errors.New("event bus projector requires brokers")
	}
	if strings.TrimSpace(o.Topic) == "" {
		return errors.New("event bus projector requires topic")
	}
	if strings.TrimSpace(o.Group) == "" {
		return errors.New("event bus projector requires consumer group")
	}
	if o.BatchSize < 1 {
		return errors.New("event bus projector requires a positive batch size")
	}
	if o.FetchMaxBytes < 1 {
		return errors.New("event bus projector requires a positive fetch byte limit")
	}
	if o.FlushInterval <= 0 {
		return errors.New("event bus projector requires a positive flush interval")
	}
	return nil
}

type Projector struct {
	client *kgo.Client
	sink   ReceiptSink
	opts   ProjectorOptions
}

func NewProjector(opts ProjectorOptions, sink ReceiptSink) (*Projector, error) {
	if sink == nil {
		return nil, errors.New("event bus projector requires a sink")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(opts.Brokers...),
		kgo.ClientID(opts.ClientID),
		kgo.ConsumerGroup(opts.Group),
		kgo.ConsumeTopics(opts.Topic),
		kgo.DisableAutoCommit(),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.FetchMaxBytes(int32(opts.FetchMaxBytes)),
	)
	if err != nil {
		return nil, fmt.Errorf("create event bus projector: %w", err)
	}
	return &Projector{client: client, sink: sink, opts: opts}, nil
}

func (p *Projector) Close() {
	if p == nil || p.client == nil {
		return
	}
	p.client.Close()
	p.client = nil
}

// Run consumes until ctx is canceled or a fatal transport/sink error occurs.
// Offsets are committed record-by-record only after the whole batch sink write
// succeeds. A crash between sink success and offset commit therefore replays a
// batch; ClickHouse ReplacingMergeTree and the unique event key absorb it.
func (p *Projector) Run(ctx context.Context) error {
	if p == nil || p.client == nil {
		return errors.New("event bus projector is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var records []*kgo.Record
	var receipts []Receipt
	for {
		pollCtx, cancel := context.WithTimeout(ctx, p.opts.FlushInterval)
		fetches := p.client.PollFetches(pollCtx)
		pollErr := pollCtx.Err()
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if errs := fetches.Errors(); len(errs) > 0 && !errors.Is(pollErr, context.DeadlineExceeded) {
			return fmt.Errorf("event bus projector poll: %v", errs)
		}
		for _, record := range fetches.Records() {
			receipt, err := receiptFromRecord(record)
			if err != nil {
				// Malformed records must not stop the whole shadow stream. The
				// record is committed with the batch and its position is logged;
				// a production projector will route these to a DLQ instead.
				log.Printf("event-bus projector: skipping invalid record partition=%d offset=%d: %v", record.Partition, record.Offset, err)
				records = append(records, record)
			} else {
				receipts = append(receipts, receipt)
				records = append(records, record)
			}
			if len(records) >= p.opts.BatchSize {
				if err := p.flush(ctx, records, receipts); err != nil {
					return err
				}
				records = records[:0]
				receipts = receipts[:0]
			}
		}
		if len(records) == 0 {
			continue
		}
		// The poll context deadline is the batch timer. If no more records
		// arrive before it expires, publish what has accumulated.
		if errors.Is(pollErr, context.DeadlineExceeded) || len(records) >= p.opts.BatchSize {
			if err := p.flush(ctx, records, receipts); err != nil {
				return err
			}
			records = records[:0]
			receipts = receipts[:0]
		}
	}
}

func (p *Projector) flush(ctx context.Context, records []*kgo.Record, receipts []Receipt) error {
	if len(records) == 0 {
		return nil
	}
	if len(receipts) > 0 {
		if err := p.sink.WriteReceipts(ctx, receipts); err != nil {
			return fmt.Errorf("event bus projector sink: %w", err)
		}
	}
	if err := p.client.CommitRecords(ctx, records...); err != nil {
		return fmt.Errorf("event bus projector commit: %w", err)
	}
	log.Printf("event-bus projector: wrote=%d skipped=%d topic=%s group=%s", len(receipts), len(records)-len(receipts), p.opts.Topic, p.opts.Group)
	return nil
}

func receiptFromRecord(record *kgo.Record) (Receipt, error) {
	if record == nil {
		return Receipt{}, errors.New("event bus projector received nil record")
	}
	var envelope Envelope
	if err := json.Unmarshal(record.Value, &envelope); err != nil {
		return Receipt{}, fmt.Errorf("decode event bus envelope: %w", err)
	}
	if envelope.SchemaVersion != SchemaVersion {
		return Receipt{}, fmt.Errorf("unsupported event bus schema %d", envelope.SchemaVersion)
	}
	if envelope.EventID == "" || envelope.PartitionKey == "" {
		return Receipt{}, errors.New("event bus envelope has no event id or partition key")
	}
	if envelope.ObservedAt.IsZero() {
		return Receipt{}, errors.New("event bus envelope has no observation time")
	}
	return Receipt{
		EventID:     envelope.EventID,
		DeviceKey:   envelope.PartitionKey,
		ObservedAt:  envelope.ObservedAt.UTC(),
		AcceptedAt:  envelope.AcceptedAt.UTC(),
		SegmentID:   envelope.SegmentID,
		ContentHash: envelope.ContentHash,
		SensorID:    envelope.SensorID,
		ScopeID:     envelope.ScopeID,
		Source:      envelope.Source,
		SourcePath:  envelope.SourcePath,
		Partition:   record.Partition,
		Offset:      record.Offset,
		Envelope:    append([]byte(nil), record.Value...),
		ConsumedAt:  time.Now().UTC(),
	}, nil
}
