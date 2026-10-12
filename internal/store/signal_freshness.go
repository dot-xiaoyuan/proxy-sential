package store

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignalArrival is the newest normalized event for one source and event type.
// AgeSeconds is computed by ClickHouse against its own clock so collector,
// database and control-plane timezone settings cannot skew freshness.
type SignalArrival struct {
	Source          string
	SourceEventType string
	LastSeen        time.Time
	AgeSeconds      int64
}

type SignalArrivalReader interface {
	SignalArrivals(context.Context, time.Duration) ([]SignalArrival, error)
}

func (s *ClickHouseStore) SignalArrivals(ctx context.Context, lookback time.Duration) ([]SignalArrival, error) {
	if lookback <= 0 || lookback > 48*time.Hour {
		return nil, fmt.Errorf("signal lookback must be between 1s and 48h")
	}
	sql := fmt.Sprintf(`SELECT source, source_event_type, toUnixTimestamp64Milli(max(timestamp)), dateDiff('second', max(timestamp), now64(6))
FROM normalized_events WHERE timestamp > now64(6) - INTERVAL %d SECOND
GROUP BY source, source_event_type FORMAT TabSeparated`, int64(lookback/time.Second))
	data, err := s.queryWithSettings(ctx, sql, map[string]string{"max_threads": "2", "max_execution_time": "10"})
	if err != nil {
		return nil, err
	}
	return parseSignalArrivals(data)
}

func parseSignalArrivals(data []byte) ([]SignalArrival, error) {
	out := []SignalArrival{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, fmt.Errorf("unexpected signal arrival row: %q", line)
		}
		millis, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("signal arrival timestamp: %w", err)
		}
		age, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("signal arrival age: %w", err)
		}
		out = append(out, SignalArrival{Source: fields[0], SourceEventType: fields[1], LastSeen: time.UnixMilli(millis).UTC(), AgeSeconds: age})
	}
	return out, scanner.Err()
}

func (s *DBStore) SignalArrivals(ctx context.Context, lookback time.Duration) ([]SignalArrival, error) {
	if s.ch == nil {
		return nil, fmt.Errorf("signal arrivals require ClickHouse storage")
	}
	return s.ch.SignalArrivals(ctx, lookback)
}
