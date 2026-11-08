package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"proxy-sentinel/internal/pagination"
)

const auxiliaryCHBudget = " SETTINGS max_threads=1,max_memory_usage=134217728,max_execution_time=5,max_rows_to_read=1000000,max_bytes_to_read=134217728,read_overflow_mode='throw' FORMAT JSONEachRow"

// Only the existing narrow search index is read; the preceding event bodies
// never leave storage. Two boundary keys prove that the requested page exists.
func (s *ClickHouseStore) PositionStreamEventIndex(ctx context.Context, q StreamEventIndexQuery, page int) (pagination.Position, error) {
	q.Cursor = ""
	offset, err := pagination.BoundaryOffset(page, q.Limit)
	if err != nil {
		return pagination.Position{}, err
	}
	where, err := streamEventIndexWhere(q)
	if err != nil {
		return pagination.Position{}, err
	}
	result := pagination.Position{Page: page, Limit: q.Limit, AsOf: time.Now().UTC()}
	if page == 1 {
		return result, nil
	}
	data, err := s.query(ctx, fmt.Sprintf("SELECT DISTINCT observed_at,event_key,content_sha256 FROM stream_event_search PREWHERE %s ORDER BY observed_at DESC,event_key DESC,content_sha256 DESC LIMIT 2 OFFSET %d%s", where, offset, auxiliaryCHBudget))
	if err != nil {
		return result, err
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) < 2 || len(lines[1]) == 0 {
		return result, pagination.ErrPageOutOfRange
	}
	var row struct {
		Observed string `json:"observed_at"`
		Key      string `json:"event_key"`
		Hash     string `json:"content_sha256"`
	}
	if err = json.Unmarshal(lines[0], &row); err != nil {
		return result, err
	}
	at, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Observed))
	if err != nil {
		return result, err
	}
	if row.Key == "" || len(row.Hash) != 64 || at.Before(q.From) || !at.Before(q.To) {
		return result, ErrInvalidStreamEventIndexQuery
	}
	raw, _ := json.Marshal(streamIndexCursor{Filter: streamIndexFilter(q), Observed: at.UTC().Format(time.RFC3339Nano), Key: row.Key, Hash: row.Hash})
	result.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	return result, nil
}

func (s *ClickHouseStore) StreamEventIndexMetadata(ctx context.Context, q StreamEventIndexQuery) (pagination.Metadata, error) {
	q.Cursor = ""
	where, err := streamEventIndexWhere(q)
	if err != nil {
		return pagination.Metadata{}, err
	}
	data, err := s.query(ctx, "SELECT uniqExact(tuple(observed_at,event_key,content_sha256)) AS total FROM stream_event_search PREWHERE "+where+auxiliaryCHBudget)
	result := pagination.Metadata{AsOf: time.Now().UTC()}
	if err != nil {
		return result, err
	}
	result.Total, err = decodeAuxiliaryTotal(data)
	return result, err
}

// ClickHouse can encode UInt64 as a JSON number or a decimal string, depending
// on a connection setting. Reject missing, fractional and overflowing counts.
func decodeAuxiliaryTotal(data []byte) (int64, error) {
	var rows []struct {
		Total json.RawMessage `json:"total"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return 0, err
	}
	if len(rows) != 1 || len(rows[0].Total) == 0 {
		return 0, fmt.Errorf("missing aggregate count")
	}
	raw := bytes.TrimSpace(rows[0].Total)
	value := string(raw)
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, err
		}
	}
	total, err := strconv.ParseInt(value, 10, 64)
	if err != nil || total < 0 {
		return 0, fmt.Errorf("invalid aggregate count %q", value)
	}
	return total, nil
}

func (s *DBStore) PositionStreamEventIndex(ctx context.Context, q StreamEventIndexQuery, page int) (pagination.Position, error) {
	return s.ch.PositionStreamEventIndex(ctx, q, page)
}
func (s *DBStore) StreamEventIndexMetadata(ctx context.Context, q StreamEventIndexQuery) (pagination.Metadata, error) {
	return s.ch.StreamEventIndexMetadata(ctx, q)
}

func (s *ClickHouseStore) PositionAIRelayUsage(ctx context.Context, q AIRelayUsageQuery, page int) (pagination.Position, error) {
	q.Cursor = ""
	offset, err := pagination.BoundaryOffset(page, q.Limit)
	if err != nil || q.Limit > 50 {
		if err == nil {
			err = fmt.Errorf("limit must be between 1 and 50")
		}
		return pagination.Position{}, err
	}
	rows, err := relayRowsSQL(q)
	if err != nil {
		return pagination.Position{}, err
	}
	result := pagination.Position{Page: page, Limit: q.Limit, AsOf: time.Now().UTC()}
	if page == 1 {
		return result, nil
	}
	data, err := s.query(ctx, fmt.Sprintf("SELECT DISTINCT ip FROM (%s) ORDER BY ip LIMIT 2 OFFSET %d%s", rows, offset, auxiliaryCHBudget))
	if err != nil {
		return result, err
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) < 2 || len(lines[1]) == 0 {
		return result, pagination.ErrPageOutOfRange
	}
	var row struct {
		IP string `json:"ip"`
	}
	if err = json.Unmarshal(lines[0], &row); err != nil {
		return result, err
	}
	result.Cursor = row.IP
	return result, nil
}
func (s *DBStore) PositionAIRelayUsage(ctx context.Context, q AIRelayUsageQuery, page int) (pagination.Position, error) {
	return s.ch.PositionAIRelayUsage(ctx, q, page)
}

func endpointObservationArguments(id string, q EndpointObservationQuery, asOf string) []any {
	nullable := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	return []any{id, q.Kind, q.Value, q.Source, nullable(q.Start), nullable(q.End), asOf}
}

func (s *PostgresStore) EndpointObservationMetadata(ctx context.Context, id string, q EndpointObservationQuery) (pagination.Metadata, error) {
	q.Cursor = ""
	if err := validateObservationQuery(&q); err != nil {
		return pagination.Metadata{}, err
	}
	c, err := observationPosition(id, q)
	if err != nil {
		return pagination.Metadata{}, err
	}
	at, _ := time.Parse(time.RFC3339Nano, c.AsOf)
	result := pagination.Metadata{AsOf: at}
	err = s.db.QueryRowContext(ctx, endpointObservationSourceSQL+" SELECT count(*) FROM observations"+endpointObservationFilterSQL, endpointObservationArguments(id, q, c.AsOf)...).Scan(&result.Total)
	return result, err
}

func (s *PostgresStore) PositionEndpointObservations(ctx context.Context, id string, q EndpointObservationQuery, page int) (pagination.Position, error) {
	q.Cursor = ""
	if err := validateObservationQuery(&q); err != nil {
		return pagination.Position{}, err
	}
	offset, err := pagination.BoundaryOffset(page, q.Limit)
	if err != nil {
		return pagination.Position{}, err
	}
	c, err := observationPosition(id, q)
	if err != nil {
		return pagination.Position{}, err
	}
	at, _ := time.Parse(time.RFC3339Nano, c.AsOf)
	result := pagination.Position{Page: page, Limit: q.Limit, AsOf: at}
	if page == 1 {
		return result, nil
	}
	args := append(endpointObservationArguments(id, q, c.AsOf), offset)
	rows, err := s.db.QueryContext(ctx, endpointObservationSourceSQL+" SELECT record_id,observed_at FROM observations"+endpointObservationFilterSQL+" ORDER BY observed_at DESC,record_id DESC LIMIT 2 OFFSET $8", args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var key string
		var stamp time.Time
		if err = rows.Scan(&key, &stamp); err != nil {
			return result, err
		}
		if count == 0 {
			c.Key = key
			c.At = stamp.UTC().Format(time.RFC3339Nano)
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if count < 2 {
		return result, pagination.ErrPageOutOfRange
	}
	raw, _ := json.Marshal(c)
	result.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	return result, nil
}
func (s *DBStore) EndpointObservationMetadata(ctx context.Context, id string, q EndpointObservationQuery) (pagination.Metadata, error) {
	return s.pg.EndpointObservationMetadata(ctx, id, q)
}
func (s *DBStore) PositionEndpointObservations(ctx context.Context, id string, q EndpointObservationQuery, page int) (pagination.Position, error) {
	return s.pg.PositionEndpointObservations(ctx, id, q, page)
}
