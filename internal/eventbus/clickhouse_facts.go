package eventbus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const discoveryFactsShadowTable = "eventbus_discovery_facts_shadow"

type ClickHouseFactSink struct {
	endpoint *url.URL
	client   *http.Client
}

func NewClickHouseFactSink(dsn string) (*ClickHouseFactSink, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, errors.New("event bus ClickHouse DSN is empty")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse event bus ClickHouse DSN: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("event bus ClickHouse DSN must be http(s)")
	}
	return &ClickHouseFactSink{endpoint: parsed, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (s *ClickHouseFactSink) WriteFacts(ctx context.Context, facts []Fact) error {
	if len(facts) == 0 {
		return nil
	}
	if s == nil || s.endpoint == nil || s.client == nil {
		return errors.New("event bus ClickHouse fact sink is closed")
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	for _, fact := range facts {
		if fact.DeviceKey == "" || fact.FactKey == "" || fact.EventID == "" || fact.ObservedAt.IsZero() {
			return errors.New("event bus fact is incomplete")
		}
		withdrawn := 0
		if fact.Withdrawn {
			withdrawn = 1
		}
		row := map[string]any{
			"device_key":       fact.DeviceKey,
			"fact_key":         fact.FactKey,
			"event_id":         fact.EventID,
			"sensor_id":        fact.SensorID,
			"source_id":        fact.SourceID,
			"site":             fact.Site,
			"domain":           fact.Domain,
			"vlan":             fact.VLAN,
			"interface_name":   fact.InterfaceName,
			"protocol":         fact.Protocol,
			"service_instance": fact.ServiceInstance,
			"ip":               fact.IP,
			"mac":              fact.MAC,
			"observed_at":      clickHouseTime(fact.ObservedAt),
			"valid_until":      clickHouseTime(fact.ValidUntil),
			"withdrawn":        withdrawn,
			"content_hash":     fact.ContentHash,
			"version":          fact.Version,
			"observation":      string(fact.Observation),
			"consumed_at":      clickHouseTime(fact.ConsumedAt),
		}
		if err := encoder.Encode(row); err != nil {
			return fmt.Errorf("encode event bus fact: %w", err)
		}
	}
	query := s.endpoint.Query()
	query.Set("query", "INSERT INTO "+discoveryFactsShadowTable+" (device_key,fact_key,event_id,sensor_id,source_id,site,domain,vlan,interface_name,protocol,service_instance,ip,mac,observed_at,valid_until,withdrawn,content_hash,version,observation,consumed_at) FORMAT JSONEachRow")
	endpoint := *s.endpoint
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &body)
	if err != nil {
		return fmt.Errorf("create event bus ClickHouse fact request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("write event bus ClickHouse facts: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("clickhouse facts status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

// ClickHouseDiscoverySink writes receipts first and then derives fact-level
// shadow rows. A fact write failure fails the batch, so the Kafka offset is not
// committed and the idempotent receipt/fact writes are replayed.
type ClickHouseDiscoverySink struct {
	receipts *ClickHouseReceiptSink
	facts    *ClickHouseFactSink
}

func NewClickHouseDiscoverySink(dsn string) (*ClickHouseDiscoverySink, error) {
	receipts, err := NewClickHouseReceiptSink(dsn)
	if err != nil {
		return nil, err
	}
	facts, err := NewClickHouseFactSink(dsn)
	if err != nil {
		return nil, err
	}
	return &ClickHouseDiscoverySink{receipts: receipts, facts: facts}, nil
}

func (s *ClickHouseDiscoverySink) WriteReceipts(ctx context.Context, receipts []Receipt) error {
	if err := s.receipts.WriteReceipts(ctx, receipts); err != nil {
		return err
	}
	facts := make([]Fact, 0, len(receipts))
	for _, receipt := range receipts {
		var envelope Envelope
		if err := json.Unmarshal(receipt.Envelope, &envelope); err != nil {
			log.Printf("event-bus facts: skip receipt event_id=%s: %v", receipt.EventID, err)
			continue
		}
		fact, err := FactFromEnvelope(envelope)
		if err != nil {
			log.Printf("event-bus facts: skip receipt event_id=%s: %v", receipt.EventID, err)
			continue
		}
		facts = append(facts, fact)
	}
	return s.facts.WriteFacts(ctx, facts)
}
