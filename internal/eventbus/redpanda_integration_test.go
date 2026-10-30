package eventbus

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestRedpandaShadowPublishes(t *testing.T) {
	rawBrokers := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_TEST_BROKERS"))
	if rawBrokers == "" {
		t.Skip("set PROXY_SENTINEL_EVENT_BUS_TEST_BROKERS to run the Redpanda shadow test")
	}
	brokers := []string{}
	for _, part := range strings.Split(rawBrokers, ",") {
		if broker := strings.TrimSpace(part); broker != "" {
			brokers = append(brokers, broker)
		}
	}
	cfg := Config{
		Enabled:        true,
		Brokers:        brokers,
		ClientID:       "shadow-integration",
		DiscoveryTopic: fmt.Sprintf("ps.test.discovery.%d", time.Now().UnixNano()),
		Linger:         5 * time.Millisecond,
		Queue:          64,
		MaxRecordBytes: 900 << 10,
	}
	producer, err := NewKafkaProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	shadow := NewShadow(cfg, producer, func(event normalized.Event) (string, string) {
		return "key-" + event.EventID, "test"
	})
	at := time.Now().UTC()
	shadow.Publish("segment-a", testSegment(at, testEvent("event-a", at), testEvent("event-b", at)))
	waitFor(t, "Redpanda delivery", func() bool { return shadow.stats.Snapshot().Published == 2 })
	if err := shadow.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if failed := shadow.stats.Snapshot().Failed; failed != 0 {
		t.Fatalf("failed deliveries = %d", failed)
	}
}
