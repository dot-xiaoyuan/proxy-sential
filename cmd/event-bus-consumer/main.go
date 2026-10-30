package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"proxy-sentinel/internal/eventbus"
)

func main() {
	brokers := flag.String("brokers", os.Getenv("PROXY_SENTINEL_EVENT_BUS_BROKERS"), "comma-separated Kafka brokers")
	topic := flag.String("topic", eventbus.DefaultDiscoveryTopic, "discovery topic")
	group := flag.String("group", "ps-discovery-eventbus-shadow-v1", "consumer group")
	clientID := flag.String("client-id", "event-bus-consumer", "Kafka client id")
	dsn := flag.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	batchSize := flag.Int("batch-size", 1000, "maximum receipts per ClickHouse insert")
	fetchBytes := flag.Int("fetch-max-bytes", 8<<20, "maximum bytes per Kafka fetch")
	flushInterval := flag.Duration("flush-interval", 500*time.Millisecond, "maximum batch wait")
	flag.Parse()

	cfg := eventbus.ProjectorOptions{
		Brokers:       splitBrokers(*brokers),
		Topic:         strings.TrimSpace(*topic),
		Group:         strings.TrimSpace(*group),
		ClientID:      strings.TrimSpace(*clientID),
		BatchSize:     *batchSize,
		FetchMaxBytes: *fetchBytes,
		FlushInterval: *flushInterval,
	}
	sink, err := eventbus.NewClickHouseDiscoverySink(*dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-consumer:", err)
		os.Exit(2)
	}
	projector, err := eventbus.NewProjector(cfg, sink)
	if err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-consumer:", err)
		os.Exit(2)
	}
	defer projector.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("event-bus-consumer started topic=%s group=%s brokers=%s", cfg.Topic, cfg.Group, strings.Join(cfg.Brokers, ","))
	if err := projector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("event-bus-consumer stopped: %v", err)
		os.Exit(1)
	}
	log.Printf("event-bus-consumer stopped")
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
