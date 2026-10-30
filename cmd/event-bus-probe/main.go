package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/eventbus"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func main() {
	mode := flag.String("mode", "consume", "produce-sample or consume")
	brokers := flag.String("brokers", os.Getenv("PROXY_SENTINEL_EVENT_BUS_BROKERS"), "comma-separated Kafka brokers")
	topic := flag.String("topic", eventbus.DefaultDiscoveryTopic, "discovery topic")
	group := flag.String("group", "event-bus-probe", "consumer group for -mode=consume")
	count := flag.Int("count", 1, "number of records to consume")
	timeout := flag.Duration("timeout", 15*time.Second, "overall command timeout")
	flag.Parse()

	cfg := eventbus.Config{
		Enabled:        true,
		Brokers:        splitBrokers(*brokers),
		ClientID:       "event-bus-probe",
		DiscoveryTopic: strings.TrimSpace(*topic),
		Linger:         5 * time.Millisecond,
		Queue:          64,
		MaxRecordBytes: 900 << 10,
	}
	if len(cfg.Brokers) == 0 || cfg.DiscoveryTopic == "" {
		fmt.Fprintln(os.Stderr, "event-bus-probe requires -brokers and -topic")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	switch *mode {
	case "produce-sample":
		if err := produceSample(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "produce sample:", err)
			os.Exit(1)
		}
	case "consume":
		if err := consume(ctx, cfg, *group, *count); err != nil {
			fmt.Fprintln(os.Stderr, "consume:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown -mode, use produce-sample or consume")
		os.Exit(2)
	}
}

func splitBrokers(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if broker := strings.TrimSpace(part); broker != "" {
			out = append(out, broker)
		}
	}
	return out
}

func sampleEvent(at time.Time) normalized.Event {
	return normalized.Event{
		SchemaVersion: "1.0",
		EventID:       fmt.Sprintf("probe-%d", at.UnixNano()),
		Source:        "event-bus-probe",
		Type:          "discovery",
		Timestamp:     at.Format(time.RFC3339Nano),
		Observer: map[string]any{
			"sensor_id":        "probe",
			"capture_scope_id": "probe-scope",
		},
		Subject: map[string]any{
			"ip":     "198.51.100.10",
			"mac":    "02:00:00:00:00:10",
			"site":   "probe",
			"domain": "probe",
		},
		Payload:    map[string]any{"origin": "ssdp", "ttl": 600},
		Confidence: 1,
	}
}

func produceSample(ctx context.Context, cfg eventbus.Config) error {
	at := time.Now().UTC()
	event := sampleEvent(at)
	key, source := discovery.StreamPartitionKey(event)
	if key == "" {
		return fmt.Errorf("sample event has no partition key")
	}
	segment := streamlog.Segment{
		Source:     "event-bus-probe",
		SourcePath: "probe://local",
		AcceptedAt: at,
		Events:     []normalized.Event{event},
	}
	envelope, err := eventbus.NewDiscoveryEnvelope("probe-segment", segment, event, key)
	if err != nil {
		return err
	}
	raw, err := envelope.Marshal()
	if err != nil {
		return err
	}
	producer, err := eventbus.NewKafkaProducer(cfg)
	if err != nil {
		return err
	}
	defer producer.Close()
	delivered := make(chan error, 1)
	err = producer.Produce(ctx, eventbus.Record{
		Topic: cfg.DiscoveryTopic,
		Key:   envelope.Key(),
		Value: raw,
		Headers: map[string]string{
			"schema_version":       fmt.Sprintf("%d", envelope.SchemaVersion),
			"partition_key_source": source,
			"event_type":           envelope.EventType,
		},
	}, func(deliveryErr error) { delivered <- deliveryErr })
	if err != nil {
		return err
	}
	select {
	case err := <-delivered:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := producer.Flush(ctx); err != nil {
		return err
	}
	fmt.Printf("produced topic=%s key=%s source=%s event=%s bytes=%d\n", cfg.DiscoveryTopic, key, source, event.EventID, len(raw))
	return nil
}

func consume(ctx context.Context, cfg eventbus.Config, group string, count int) error {
	envelopes, err := eventbus.ConsumeFromStart(ctx, cfg, group, count, 15*time.Second)
	if err != nil {
		return err
	}
	for _, envelope := range envelopes {
		fmt.Printf("consumed event=%s key=%s schema=%d observed=%s segment=%s\n",
			envelope.EventID, envelope.PartitionKey, envelope.SchemaVersion,
			envelope.ObservedAt.Format(time.RFC3339Nano), envelope.SegmentID)
	}
	return nil
}
