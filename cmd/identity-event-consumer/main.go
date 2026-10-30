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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
)

type identityEvent struct {
	SchemaVersion   int             `json:"schema_version"`
	SessionID       string          `json:"session_id"`
	AccountID       string          `json:"account_id"`
	EndpointID      string          `json:"endpoint_id"`
	IP              string          `json:"ip"`
	MAC             string          `json:"mac"`
	Source          string          `json:"source"`
	SensorID        string          `json:"sensor_id"`
	StartedAt       *time.Time      `json:"started_at"`
	EndedAt         *time.Time      `json:"ended_at"`
	LastConfirmedAt *time.Time      `json:"last_confirmed_at"`
	IdentityConf    float64         `json:"identity_confidence"`
	VLAN            string          `json:"vlan"`
	NASIP           string          `json:"nas_ip"`
	SessionStatus   string          `json:"session_status"`
	PolicyMetadata  json.RawMessage `json:"policy_metadata"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func main() {
	brokers := flag.String("brokers", os.Getenv("PROXY_SENTINEL_EVENT_BUS_BROKERS"), "Kafka brokers")
	topic := flag.String("topic", "ps.identity.events.v1", "identity topic")
	group := flag.String("group", "ps-identity-eventbus-shadow-v1", "consumer group")
	pgDSN := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	flag.Parse()
	if strings.TrimSpace(*brokers) == "" || strings.TrimSpace(*pgDSN) == "" {
		fmt.Fprintln(os.Stderr, "identity-event-consumer requires brokers and postgres-dsn")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, *pgDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity-event-consumer:", err)
		os.Exit(2)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "identity-event-consumer:", err)
		os.Exit(2)
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(splitBrokers(*brokers)...),
		kgo.ClientID("identity-event-consumer"),
		kgo.ConsumerGroup(*group),
		kgo.ConsumeTopics(*topic),
		kgo.DisableAutoCommit(),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.FetchMaxBytes(8<<20),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity-event-consumer:", err)
		os.Exit(2)
	}
	defer client.Close()
	log.Printf("identity-event-consumer started topic=%s group=%s", *topic, *group)
	var batch []*kgo.Record
	var events []identityEvent
	for {
		pollCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		fetches := client.PollFetches(pollCtx)
		pollErr := pollCtx.Err()
		cancel()
		if ctx.Err() != nil {
			return
		}
		if errs := fetches.Errors(); len(errs) > 0 && !errors.Is(pollErr, context.DeadlineExceeded) {
			log.Printf("identity-event-consumer poll: %v", errs)
			continue
		}
		for _, record := range fetches.Records() {
			var event identityEvent
			if err := json.Unmarshal(record.Value, &event); err != nil || event.SessionID == "" || event.UpdatedAt.IsZero() {
				log.Printf("identity-event-consumer: skip invalid partition=%d offset=%d", record.Partition, record.Offset)
				batch = append(batch, record)
				continue
			}
			batch = append(batch, record)
			events = append(events, event)
			if len(batch) >= 500 {
				if err := flush(ctx, pool, client, batch, events); err != nil {
					log.Printf("identity-event-consumer: %v", err)
					return
				}
				batch, events = nil, nil
			}
		}
		if len(batch) > 0 && errors.Is(pollErr, context.DeadlineExceeded) {
			if err := flush(ctx, pool, client, batch, events); err != nil {
				log.Printf("identity-event-consumer: %v", err)
				return
			}
			batch, events = nil, nil
		}
	}
}

func flush(ctx context.Context, pool *pgxpool.Pool, client *kgo.Client, records []*kgo.Record, events []identityEvent) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, event := range events {
		_, err := tx.Exec(ctx, `INSERT INTO identity_session_shadow(
 session_id,account_id,endpoint_id,ip,mac,source,sensor_id,started_at,ended_at,last_confirmed_at,
 identity_confidence,vlan,nas_ip,session_status,policy_metadata,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT(session_id) DO UPDATE SET
 account_id=EXCLUDED.account_id,endpoint_id=EXCLUDED.endpoint_id,ip=EXCLUDED.ip,mac=EXCLUDED.mac,
 source=EXCLUDED.source,sensor_id=EXCLUDED.sensor_id,started_at=EXCLUDED.started_at,
 ended_at=EXCLUDED.ended_at,last_confirmed_at=EXCLUDED.last_confirmed_at,
 identity_confidence=EXCLUDED.identity_confidence,vlan=EXCLUDED.vlan,nas_ip=EXCLUDED.nas_ip,
 session_status=EXCLUDED.session_status,policy_metadata=EXCLUDED.policy_metadata,updated_at=EXCLUDED.updated_at
 WHERE EXCLUDED.updated_at >= identity_session_shadow.updated_at`,
			event.SessionID, event.AccountID, event.EndpointID, event.IP, event.MAC, event.Source, event.SensorID,
			event.StartedAt, event.EndedAt, event.LastConfirmedAt, event.IdentityConf, event.VLAN, event.NASIP,
			event.SessionStatus, event.PolicyMetadata, event.UpdatedAt)
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := client.CommitRecords(ctx, records...); err != nil {
		return err
	}
	log.Printf("identity-event-consumer: wrote=%d skipped=%d", len(events), len(records)-len(events))
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
