package main

import (
	"context"
	"encoding/json"
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
	"proxy-sentinel/internal/store"
)

func main() {
	var replayFiles replayFileFlags
	brokers := flag.String("brokers", os.Getenv("PROXY_SENTINEL_EVENT_BUS_BROKERS"), "comma-separated Kafka brokers")
	topic := flag.String("topic", eventbus.DefaultDiscoveryTopic, "discovery topic")
	group := flag.String("group", "ps-discovery-eventbus-shadow-v1", "consumer group")
	clientID := flag.String("client-id", "event-bus-consumer", "Kafka client id")
	dsn := flag.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	pgDSN := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	normalizedOnly := flag.Bool("normalized-only", false, "retire duplicate receipt/fact projections; preserve normalized events and committed offsets")
	batchSize := flag.Int("batch-size", 1000, "maximum receipts per ClickHouse insert")
	fetchBytes := flag.Int("fetch-max-bytes", 8<<20, "maximum bytes per Kafka fetch")
	flushInterval := flag.Duration("flush-interval", 500*time.Millisecond, "maximum batch wait")
	quarantineDir := flag.String("quarantine-dir", "/var/lib/proxy-sentinel/eventbus-quarantine", "durable invalid-record quarantine directory")
	flag.Var(&replayFiles, "replay-file", "explicit quarantine file basename to replay; repeat 1..32 times, never scans the directory")
	flag.Parse()

	cfg := eventbus.ProjectorOptions{
		Brokers:       splitBrokers(*brokers),
		Topic:         strings.TrimSpace(*topic),
		Group:         strings.TrimSpace(*group),
		ClientID:      strings.TrimSpace(*clientID),
		BatchSize:     *batchSize,
		FetchMaxBytes: *fetchBytes,
		FlushInterval: *flushInterval,
		QuarantineDir: strings.TrimSpace(*quarantineDir),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	chStore, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: *dsn})
	if err != nil {
		log.Fatal(err)
	}
	normalizedSink := eventbus.NewClickHouseNormalizedSink(chStore)
	var sink eventbus.ReceiptSink = normalizedSink
	if !*normalizedOnly {
		log.Printf("event-bus-consumer full sink is a shadow projection; use -normalized-only for the reliable producer canary until each full-mode destination has independent replay reconciliation")
		chSink, err := eventbus.NewClickHouseDiscoverySink(*dsn)
		if err != nil {
			log.Fatal(err)
		}
		pgSink, err := eventbus.NewPostgresFactSink(ctx, *pgDSN)
		if err != nil {
			log.Fatal(err)
		}
		defer pgSink.Close()
		sink = eventbus.NewMultiSink(chSink, pgSink, normalizedSink)
	}
	if len(replayFiles) > 0 {
		mode := "full"
		if *normalizedOnly {
			mode = "normalized-only"
		}
		replayCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		results, replayErr := eventbus.ReplayQuarantinedRecords(replayCtx, cfg.QuarantineDir, cfg.Topic, mode, replayFiles, sink)
		for _, item := range results {
			encoded, _ := json.Marshal(item)
			fmt.Println(string(encoded))
		}
		if replayErr != nil {
			log.Fatalf("event-bus-consumer replay stopped after %d audited records: %v", len(results), replayErr)
		}
		return
	}
	projector, err := eventbus.NewProjector(cfg, sink)
	if err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-consumer:", err)
		os.Exit(2)
	}
	defer projector.Close()

	log.Printf("event-bus-consumer started topic=%s group=%s brokers=%s normalized_only=%t; commits follow sink confirmation, without cross-database exactly-once semantics", cfg.Topic, cfg.Group, strings.Join(cfg.Brokers, ","), *normalizedOnly)
	if err := projector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("event-bus-consumer stopped: %v", err)
		os.Exit(1)
	}
	log.Printf("event-bus-consumer stopped")
}

type replayFileFlags []string

func (f *replayFileFlags) String() string { return strings.Join(*f, ",") }
func (f *replayFileFlags) Set(name string) error {
	if len(*f) >= 32 {
		return errors.New("at most 32 explicit replay files")
	}
	if name == "" {
		return errors.New("replay file basename is empty")
	}
	*f = append(*f, name)
	return nil
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
