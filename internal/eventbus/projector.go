package eventbus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"proxy-sentinel/internal/normalized"
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

// ReceiptSink is a per-destination confirmation boundary. The projector
// commits Kafka offsets only after the sink returns success. Each destination
// owns its replay behavior; this interface does not provide a cross-database
// transaction or exactly-once delivery.
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
	QuarantineDir string
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
// Offsets are committed only after the whole batch sink write succeeds. A
// crash between sink success and offset commit replays the batch. The
// normalized-only sink synchronously checks the retained event ID and body
// before inserting, but independent concurrent writers still need isolation;
// ReplacingMergeTree merges are not an immediate deduplication guarantee.
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
			receipt, include, err := p.receiptOrQuarantine(record, time.Now().UTC())
			if err != nil {
				// No sink or Kafka offset commit has occurred for this fetched
				// batch. Earlier records remain replayable with this position.
				return err
			}
			if include {
				receipts = append(receipts, receipt)
			}
			records = append(records, record)
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
	log.Printf("event-bus projector: wrote=%d quarantined=%d topic=%s group=%s", len(receipts), len(records)-len(receipts), p.opts.Topic, p.opts.Group)
	return nil
}

const (
	// normalized_events has a seven-day observation-time TTL. Its retained
	// body can prove an event ID only inside the six-day canary window. The
	// one-minute guard prevents a record crossing the proof boundary between
	// classification and the sink's independent check.
	normalizedProofWindow          = 6 * 24 * time.Hour
	normalizedProofBoundaryGuard   = time.Minute
	normalizedProofWindowGapReason = "normalized_event_id_proof_window_exceeded"
	normalizedFutureGapReason      = "normalized_event_observation_more_than_one_hour_ahead"
)

// receiptOrQuarantine preserves the original Kafka position and envelope as
// an explicit projection gap before allowing its offset into a committed
// batch. An old observation remains in its authoritative stream body; this
// step neither writes normalized_events nor claims that projection succeeded.
func (p *Projector) receiptOrQuarantine(record *kgo.Record, now time.Time) (Receipt, bool, error) {
	if record == nil {
		return Receipt{}, false, errors.New("event bus projector received nil record")
	}
	receipt, err := receiptFromRecord(record)
	reason := ""
	if err != nil {
		reason = err.Error()
	} else if receipt.ObservedAt.Before(now.Add(-normalizedProofWindow + normalizedProofBoundaryGuard)) {
		reason = normalizedProofWindowGapReason
	} else if receipt.ObservedAt.After(now.Add(time.Hour - normalizedProofBoundaryGuard)) {
		reason = normalizedFutureGapReason
	}
	if reason == "" {
		return receipt, true, nil
	}
	path, quarantineErr := quarantineInvalidRecord(p.opts.QuarantineDir, record, reason)
	if quarantineErr != nil {
		return Receipt{}, false, fmt.Errorf("event bus projector cannot quarantine partition=%d offset=%d: %w", record.Partition, record.Offset, quarantineErr)
	}
	log.Printf("event-bus projector: quarantined record partition=%d offset=%d reason=%s path=%s", record.Partition, record.Offset, reason, path)
	return Receipt{}, false, nil
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
	if envelope.ObservedAt.IsZero() || envelope.AcceptedAt.IsZero() || envelope.SegmentID == "" {
		return Receipt{}, errors.New("event bus envelope has no observation, acceptance or segment position")
	}
	var event normalized.Event
	if err := json.Unmarshal(envelope.Event, &event); err != nil {
		return Receipt{}, fmt.Errorf("decode event bus event: %w", err)
	}
	observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil || event.EventID != envelope.EventID || event.Type == "" || event.Type != envelope.EventType || !observed.Equal(envelope.ObservedAt) {
		return Receipt{}, errors.New("event bus event identity, type or observation time conflicts with envelope")
	}
	hash := sha256.Sum256(envelope.Event)
	if envelope.ContentHash != "sha256:"+hex.EncodeToString(hash[:]) {
		return Receipt{}, errors.New("event bus event content hash conflicts with envelope")
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
