package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresFactSink writes the same fact-level shadow rows to PostgreSQL. It is
// deliberately separate from the final device_current projection: no query
// path reads this table and no legacy table is updated.
type PostgresFactSink struct {
	pool *pgxpool.Pool
}

func NewPostgresFactSink(ctx context.Context, dsn string) (*PostgresFactSink, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, errors.New("event bus PostgreSQL DSN is empty")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse event bus PostgreSQL DSN: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create event bus PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping event bus PostgreSQL: %w", err)
	}
	return &PostgresFactSink{pool: pool}, nil
}

func (s *PostgresFactSink) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
		s.pool = nil
	}
}

type postgresFactRow struct {
	DeviceKey       string          `json:"device_key"`
	FactKey         string          `json:"fact_key"`
	EventID         string          `json:"event_id"`
	SensorID        string          `json:"sensor_id"`
	SourceID        string          `json:"source_id"`
	Site            string          `json:"site"`
	Domain          string          `json:"domain"`
	VLAN            string          `json:"vlan"`
	InterfaceName   string          `json:"interface_name"`
	Protocol        string          `json:"protocol"`
	ServiceInstance string          `json:"service_instance"`
	IP              string          `json:"ip"`
	MAC             string          `json:"mac"`
	ObservedAt      time.Time       `json:"observed_at"`
	ValidUntil      *time.Time      `json:"valid_until"`
	Withdrawn       bool            `json:"withdrawn"`
	ContentHash     string          `json:"content_hash"`
	Version         int64           `json:"version"`
	Observation     json.RawMessage `json:"observation"`
}

func (s *PostgresFactSink) WriteReceipts(ctx context.Context, receipts []Receipt) error {
	if len(receipts) == 0 {
		return nil
	}
	if s == nil || s.pool == nil {
		return errors.New("event bus PostgreSQL fact sink is closed")
	}
	rows := make([]postgresFactRow, 0, len(receipts))
	for _, receipt := range receipts {
		var envelope Envelope
		if err := json.Unmarshal(receipt.Envelope, &envelope); err != nil {
			continue
		}
		fact, err := FactFromEnvelope(envelope)
		if err != nil {
			continue
		}
		var validUntil *time.Time
		if !fact.ValidUntil.IsZero() {
			value := fact.ValidUntil
			validUntil = &value
		}
		rows = append(rows, postgresFactRow{
			DeviceKey:       fact.DeviceKey,
			FactKey:         fact.FactKey,
			EventID:         fact.EventID,
			SensorID:        fact.SensorID,
			SourceID:        fact.SourceID,
			Site:            fact.Site,
			Domain:          fact.Domain,
			VLAN:            fact.VLAN,
			InterfaceName:   fact.InterfaceName,
			Protocol:        fact.Protocol,
			ServiceInstance: fact.ServiceInstance,
			IP:              fact.IP,
			MAC:             fact.MAC,
			ObservedAt:      fact.ObservedAt,
			ValidUntil:      validUntil,
			Withdrawn:       fact.Withdrawn,
			ContentHash:     fact.ContentHash,
			Version:         int64(fact.Version),
			Observation:     json.RawMessage(fact.Observation),
		})
	}
	if len(rows) == 0 {
		return nil
	}
	// One INSERT cannot affect the same conflict target twice. Keep only the
	// greatest (version,event_id) row for each device/fact in the batch.
	unique := make(map[string]postgresFactRow, len(rows))
	for _, row := range rows {
		key := row.DeviceKey + "\x00" + row.FactKey
		existing, ok := unique[key]
		if !ok || row.Version > existing.Version || (row.Version == existing.Version && row.EventID > existing.EventID) {
			unique[key] = row
		}
	}
	rows = rows[:0]
	for _, row := range unique {
		rows = append(rows, row)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("encode event bus PostgreSQL facts: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO discovery_service_facts_shadow(
    device_key,fact_key,event_id,sensor_id,source_id,site,domain,vlan,interface_name,
    protocol,service_instance,ip,mac,observed_at,valid_until,withdrawn,content_hash,version,observation,updated_at)
SELECT v.device_key,v.fact_key,v.event_id,v.sensor_id,v.source_id,v.site,v.domain,v.vlan,v.interface_name,
       v.protocol,v.service_instance,v.ip,v.mac,v.observed_at,v.valid_until,v.withdrawn,v.content_hash,v.version,v.observation,now()
FROM jsonb_to_recordset($1::jsonb) AS v(
    device_key text,fact_key text,event_id text,sensor_id text,source_id text,site text,domain text,vlan text,
    interface_name text,protocol text,service_instance text,ip text,mac text,observed_at timestamptz,
    valid_until timestamptz,withdrawn boolean,content_hash text,version bigint,observation jsonb)
ON CONFLICT (device_key,fact_key) DO UPDATE SET
    event_id=EXCLUDED.event_id,
    sensor_id=EXCLUDED.sensor_id,
    source_id=EXCLUDED.source_id,
    site=EXCLUDED.site,
    domain=EXCLUDED.domain,
    vlan=EXCLUDED.vlan,
    interface_name=EXCLUDED.interface_name,
    protocol=EXCLUDED.protocol,
    service_instance=EXCLUDED.service_instance,
    ip=EXCLUDED.ip,
    mac=EXCLUDED.mac,
    observed_at=EXCLUDED.observed_at,
    valid_until=EXCLUDED.valid_until,
    withdrawn=EXCLUDED.withdrawn,
    content_hash=EXCLUDED.content_hash,
    version=EXCLUDED.version,
    observation=EXCLUDED.observation,
    updated_at=now()
WHERE EXCLUDED.version > discovery_service_facts_shadow.version
   OR (EXCLUDED.version = discovery_service_facts_shadow.version
       AND EXCLUDED.event_id > discovery_service_facts_shadow.event_id)`, raw)
	if err != nil {
		return fmt.Errorf("write event bus PostgreSQL facts: %w", err)
	}
	return nil
}
