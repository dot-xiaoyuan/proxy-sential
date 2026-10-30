package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// ConsumeFromStart is a bounded diagnostic consumer used by the probe and the
// optional Redpanda integration test. Production projectors will use explicit
// offsets and sink acknowledgements, not this helper.
func ConsumeFromStart(ctx context.Context, cfg Config, group string, count int, timeout time.Duration) ([]Envelope, error) {
	if len(cfg.Brokers) == 0 || cfg.DiscoveryTopic == "" || group == "" || count < 1 {
		return nil, errors.New("event bus consume requires brokers, topic, group and count")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID+"-probe"),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(cfg.DiscoveryTopic),
		kgo.DisableAutoCommit(),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := make([]Envelope, 0, count)
	for len(out) < count {
		fetches := client.PollFetches(pollCtx)
		if err := pollCtx.Err(); err != nil {
			return out, err
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			return out, fmt.Errorf("event bus consume: %v", errs)
		}
		var decodeErr error
		fetches.EachRecord(func(record *kgo.Record) {
			if decodeErr != nil {
				return
			}
			var envelope Envelope
			if err := json.Unmarshal(record.Value, &envelope); err != nil {
				decodeErr = fmt.Errorf("decode event bus envelope: %w", err)
				return
			}
			if envelope.SchemaVersion != SchemaVersion {
				decodeErr = fmt.Errorf("unsupported event bus schema %d", envelope.SchemaVersion)
				return
			}
			out = append(out, envelope)
		})
		if decodeErr != nil {
			return out, decodeErr
		}
		if err := client.CommitUncommittedOffsets(pollCtx); err != nil {
			return out, err
		}
	}
	return out, nil
}
