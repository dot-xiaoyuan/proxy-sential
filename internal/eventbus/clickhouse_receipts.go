package eventbus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const discoveryReceiptsTable = "eventbus_discovery_receipts"

// ClickHouseReceiptSink writes shadow receipts through the ClickHouse HTTP
// interface. The DSN is the same URL form used by the control plane; query
// credentials stay in the URL and are never logged by this package.
type ClickHouseReceiptSink struct {
	endpoint *url.URL
	client   *http.Client
}

func NewClickHouseReceiptSink(dsn string) (*ClickHouseReceiptSink, error) {
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
	return &ClickHouseReceiptSink{
		endpoint: parsed,
		client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *ClickHouseReceiptSink) WriteReceipts(ctx context.Context, receipts []Receipt) error {
	if len(receipts) == 0 {
		return nil
	}
	if s == nil || s.endpoint == nil || s.client == nil {
		return errors.New("event bus ClickHouse sink is closed")
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	for _, receipt := range receipts {
		if receipt.EventID == "" || receipt.DeviceKey == "" || receipt.ObservedAt.IsZero() {
			return errors.New("event bus receipt is incomplete")
		}
		row := map[string]any{
			"event_id":        receipt.EventID,
			"device_key":      receipt.DeviceKey,
			"observed_at":     clickHouseTime(receipt.ObservedAt),
			"accepted_at":     clickHouseTime(receipt.AcceptedAt),
			"segment_id":      receipt.SegmentID,
			"content_hash":    receipt.ContentHash,
			"sensor_id":       receipt.SensorID,
			"scope_id":        receipt.ScopeID,
			"source":          receipt.Source,
			"source_path":     receipt.SourcePath,
			"kafka_partition": receipt.Partition,
			"kafka_offset":    receipt.Offset,
			"envelope":        string(receipt.Envelope),
			"consumed_at":     clickHouseTime(receipt.ConsumedAt),
		}
		if err := encoder.Encode(row); err != nil {
			return fmt.Errorf("encode event bus receipt: %w", err)
		}
	}
	query := s.endpoint.Query()
	query.Set("query", "INSERT INTO "+discoveryReceiptsTable+" (event_id,device_key,observed_at,accepted_at,segment_id,content_hash,sensor_id,scope_id,source,source_path,kafka_partition,kafka_offset,envelope,consumed_at) FORMAT JSONEachRow")
	endpoint := *s.endpoint
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &body)
	if err != nil {
		return fmt.Errorf("create event bus ClickHouse request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("write event bus ClickHouse receipts: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("clickhouse receipts status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

func clickHouseTime(t time.Time) string {
	if t.IsZero() {
		return "1970-01-01 00:00:00.000000"
	}
	return t.UTC().Format("2006-01-02 15:04:05.000000")
}
