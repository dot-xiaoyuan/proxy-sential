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
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"proxy-sentinel/internal/eventbus"
)

const relayTopic = "ps.identity.events.v1"

type identityEvent struct {
	SchemaVersion   int             `json:"schema_version"`
	EventType       string          `json:"event_type"`
	SessionID       string          `json:"session_id"`
	AccountID       string          `json:"account_id"`
	EndpointID      string          `json:"endpoint_id"`
	IP              string          `json:"ip"`
	MAC             string          `json:"mac"`
	Source          string          `json:"source"`
	SensorID        string          `json:"sensor_id"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	EndedAt         *time.Time      `json:"ended_at,omitempty"`
	LastConfirmedAt *time.Time      `json:"last_confirmed_at,omitempty"`
	IdentityConf    float64         `json:"identity_confidence"`
	VLAN            string          `json:"vlan"`
	NASIP           string          `json:"nas_ip"`
	SessionStatus   string          `json:"session_status"`
	PolicyMetadata  json.RawMessage `json:"policy_metadata,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func main() {
	pgDSN := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	brokers := flag.String("brokers", os.Getenv("PROXY_SENTINEL_EVENT_BUS_BROKERS"), "Kafka brokers")
	topic := flag.String("topic", relayTopic, "identity topic")
	clientID := flag.String("client-id", "identity-event-relay", "Kafka client id")
	interval := flag.Duration("interval", time.Second, "poll interval")
	lookback := flag.Duration("lookback", time.Minute, "initial lookback when no cursor exists")
	flag.Parse()
	if strings.TrimSpace(*pgDSN) == "" || strings.TrimSpace(*brokers) == "" {
		fmt.Fprintln(os.Stderr, "identity-event-relay requires postgres-dsn and brokers")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, *pgDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity-event-relay:", err)
		os.Exit(2)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "identity-event-relay:", err)
		os.Exit(2)
	}
	producer, err := eventbus.NewKafkaProducer(eventbus.Config{
		Enabled: true, Brokers: splitBrokers(*brokers), ClientID: *clientID,
		DiscoveryTopic: *topic, Linger: 5 * time.Millisecond, Queue: 8192, MaxRecordBytes: 900 << 10,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity-event-relay:", err)
		os.Exit(2)
	}
	defer producer.Close()
	if err := ensureCursor(ctx, pool, *lookback); err != nil {
		fmt.Fprintln(os.Stderr, "identity-event-relay:", err)
		os.Exit(2)
	}
	log.Printf("identity-event-relay started topic=%s brokers=%s", *topic, *brokers)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		if err := relayBatch(ctx, pool, producer, *topic); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("identity-event-relay: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func ensureCursor(ctx context.Context, pool *pgxpool.Pool, lookback time.Duration) error {
	_, err := pool.Exec(ctx, `INSERT INTO identity_event_relay_state(singleton,updated_at,session_id)
VALUES(TRUE, now()-$1::interval, '') ON CONFLICT(singleton) DO NOTHING`, fmt.Sprintf("%d seconds", int(lookback.Seconds())))
	return err
}

type sessionRow struct {
	SessionID, AccountID, EndpointID, IP, MAC, Source, SensorID, VLAN, NASIP, Status string
	Started, Ended, Confirmed, Updated                                               *time.Time
	Confidence                                                                       float64
	Policy                                                                           []byte
}

func relayBatch(ctx context.Context, pool *pgxpool.Pool, producer *eventbus.KafkaProducer, topic string) error {
	var cursor time.Time
	var cursorID string
	if err := pool.QueryRow(ctx, `SELECT updated_at,session_id FROM identity_event_relay_state WHERE singleton=TRUE`).Scan(&cursor, &cursorID); err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `SELECT session_id,coalesce(account_id,''),coalesce(endpoint_id,''),
coalesce(host(ip),''),coalesce(mac,''),coalesce(source,''),coalesce(sensor_id,''),
started_at,ended_at,last_confirmed_at,identity_confidence,coalesce(vlan,''),coalesce(host(nas_ip),''),
coalesce(session_status,''),coalesce(policy_metadata,'{}'::jsonb),updated_at
FROM account_sessions
WHERE (updated_at,session_id) > ($1,$2)
ORDER BY updated_at,session_id LIMIT 500`, cursor, cursorID)
	if err != nil {
		return err
	}
	list := []sessionRow{}
	for rows.Next() {
		var r sessionRow
		if err := rows.Scan(&r.SessionID, &r.AccountID, &r.EndpointID, &r.IP, &r.MAC, &r.Source, &r.SensorID,
			&r.Started, &r.Ended, &r.Confirmed, &r.Confidence, &r.VLAN, &r.NASIP, &r.Status, &r.Policy, &r.Updated); err != nil {
			rows.Close()
			return err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(list) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, r := range list {
		event := identityEvent{
			SchemaVersion: 1, EventType: "identity_session", SessionID: r.SessionID,
			AccountID: r.AccountID, EndpointID: r.EndpointID, IP: r.IP, MAC: r.MAC,
			Source: r.Source, SensorID: r.SensorID, StartedAt: r.Started, EndedAt: r.Ended,
			LastConfirmedAt: r.Confirmed, IdentityConf: r.Confidence, VLAN: r.VLAN,
			NASIP: r.NASIP, SessionStatus: r.Status, PolicyMetadata: json.RawMessage(r.Policy), UpdatedAt: derefTime(r.Updated),
		}
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		wg.Add(1)
		if err := producer.Produce(ctx, eventbus.Record{
			Topic: topic, Key: []byte(r.SessionID), Value: raw,
			Headers: map[string]string{"event_type": "identity_session", "schema_version": "1"},
		}, func(deliveryErr error) {
			defer wg.Done()
			if deliveryErr != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = deliveryErr
				}
				mu.Unlock()
			}
		}); err != nil {
			wg.Done()
			return err
		}
	}
	wg.Wait()
	if err := producer.Flush(ctx); err != nil {
		return err
	}
	if firstErr != nil {
		return firstErr
	}
	last := list[len(list)-1]
	if _, err := pool.Exec(ctx, `UPDATE identity_event_relay_state SET updated_at=$1,session_id=$2 WHERE singleton=TRUE`, derefTime(last.Updated), last.SessionID); err != nil {
		return err
	}
	log.Printf("identity-event-relay: produced=%d through=%s", len(list), derefTime(last.Updated).UTC().Format(time.RFC3339Nano))
	return nil
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
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
