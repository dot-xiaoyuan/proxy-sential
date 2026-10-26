package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

// StreamEventIndexQuery is deliberately narrower than the legacy event query.
// A scope and at most fifteen minutes are required to keep ClickHouse reads
// bounded as additional protocols are enabled.
type StreamEventIndexQuery struct {
	SensorID        string
	SubjectIP       string
	Epoch           string
	ObservationOnly bool
	ScopeID         string
	Protocol        string
	From            time.Time
	To              time.Time
	Limit           int
	Cursor          string
}

type StreamEventIndexItem struct {
	ObservedAt time.Time     `json:"observed_at"`
	EventKey   string        `json:"event_key"`
	Protocol   string        `json:"protocol"`
	EventType  string        `json:"event_type"`
	Source     string        `json:"source"`
	SensorID   string        `json:"sensor_id"`
	SubjectIP  string        `json:"subject_ip,omitempty"`
	SubjectMAC string        `json:"subject_mac,omitempty"`
	SrcIP      string        `json:"src_ip,omitempty"`
	DstIP      string        `json:"dst_ip,omitempty"`
	SrcPort    uint32        `json:"src_port,omitempty"`
	DstPort    uint32        `json:"dst_port,omitempty"`
	Body       StreamBodyRef `json:"body_ref"`
}

type StreamEventIndexPage struct {
	Items      []StreamEventIndexItem `json:"events"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type StreamEventIndexReader interface {
	ListStreamEventIndex(context.Context, StreamEventIndexQuery) (StreamEventIndexPage, error)
	GetStreamEventByRef(context.Context, StreamBodyRef) (normalized.Event, bool, error)
}

type streamIndexCursor struct {
	Filter   string `json:"filter"`
	Observed string `json:"observed"`
	Key      string `json:"key"`
	Hash     string `json:"hash"`
}

var ErrInvalidStreamEventIndexQuery = errors.New("invalid bounded stream event query")

func streamIndexFilter(query StreamEventIndexQuery) string {
	parts := []string{query.ScopeID, query.Protocol, query.From.UTC().Format(time.RFC3339Nano), query.To.UTC().Format(time.RFC3339Nano)}
	if query.SubjectIP != "" || query.SensorID != "" || query.Epoch != "" || query.ObservationOnly {
		parts = append(parts, query.SubjectIP, query.SensorID, query.Epoch, fmt.Sprint(query.ObservationOnly))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func (s *ClickHouseStore) ListStreamEventIndex(ctx context.Context, query StreamEventIndexQuery) (StreamEventIndexPage, error) {
	if query.SubjectIP != "" {
		ip, err := netip.ParseAddr(query.SubjectIP)
		if err != nil || ip.Zone() != "" {
			return StreamEventIndexPage{}, ErrInvalidStreamEventIndexQuery
		}
	}
	if len(query.SensorID) > 256 || len(query.Epoch) > 256 || strings.ContainsAny(query.Epoch, "\x00:") ||
		(query.ObservationOnly && (query.SubjectIP == "" || query.SensorID == "" || query.Epoch == "" || (query.Protocol != "" && !trafficObservationProtocol(query.Protocol)))) {
		return StreamEventIndexPage{}, ErrInvalidStreamEventIndexQuery
	}
	if s == nil || query.ScopeID == "" || len(query.ScopeID) > 256 || len(query.Protocol) > 128 ||
		query.From.IsZero() || !query.To.After(query.From) || query.To.Sub(query.From) > 15*time.Minute ||
		query.Limit < 1 || query.Limit > 100 {
		return StreamEventIndexPage{}, fmt.Errorf("%w: scope, at most fifteen minutes and limit 1..100 required", ErrInvalidStreamEventIndexQuery)
	}
	where := "scope_id=" + chQuote(query.ScopeID) +
		" AND observed_at>=parseDateTime64BestEffort(" + chQuote(query.From.UTC().Format(time.RFC3339Nano)) + ",6)" +
		" AND observed_at<parseDateTime64BestEffort(" + chQuote(query.To.UTC().Format(time.RFC3339Nano)) + ",6)"
	if query.Protocol != "" {
		where += " AND protocol=" + chQuote(query.Protocol)
	}
	if query.SubjectIP != "" {
		where += " AND subject_ip=" + chQuote(query.SubjectIP)
	}
	if query.SensorID != "" {
		where += " AND sensor_id=" + chQuote(query.SensorID)
	}
	if query.Epoch != "" {
		where += " AND startsWith(event_key," + chQuote(query.Epoch+":") + ")"
	}
	if query.ObservationOnly {
		where += " AND protocol IN ('handshake','ttl','hop_limit')"
	}
	if query.Cursor != "" {
		if len(query.Cursor) > 1024 {
			return StreamEventIndexPage{}, fmt.Errorf("%w: cursor is too long", ErrInvalidStreamEventIndexQuery)
		}
		raw, err := base64.RawURLEncoding.DecodeString(query.Cursor)
		if err != nil {
			return StreamEventIndexPage{}, fmt.Errorf("%w: cursor encoding", ErrInvalidStreamEventIndexQuery)
		}
		var cursor streamIndexCursor
		if json.Unmarshal(raw, &cursor) != nil || cursor.Filter != streamIndexFilter(query) || cursor.Key == "" || len(cursor.Hash) != 64 {
			return StreamEventIndexPage{}, fmt.Errorf("%w: cursor does not match query", ErrInvalidStreamEventIndexQuery)
		}
		observed, err := time.Parse(time.RFC3339Nano, cursor.Observed)
		if err != nil || observed.Before(query.From) || !observed.Before(query.To) {
			return StreamEventIndexPage{}, fmt.Errorf("%w: cursor time", ErrInvalidStreamEventIndexQuery)
		}
		stamp := "parseDateTime64BestEffort(" + chQuote(cursor.Observed) + ",6)"
		where += " AND (observed_at<" + stamp + " OR (observed_at=" + stamp +
			" AND (event_key<" + chQuote(cursor.Key) + " OR (event_key=" + chQuote(cursor.Key) +
			" AND content_sha256<" + chQuote(cursor.Hash) + "))))"
	}
	readBudget := ""
	if query.ObservationOnly {
		readBudget = ",max_rows_to_read=1000000,max_bytes_to_read=134217728,read_overflow_mode='throw'"
	}
	sql := fmt.Sprintf(`SELECT DISTINCT observed_at,event_key,content_sha256,scope_id,protocol,event_type,source,sensor_id,subject_ip,subject_mac,src_ip,dst_ip,src_port,dst_port,archive_month,retention_class,body_ref
FROM stream_event_search PREWHERE %s
ORDER BY observed_at DESC,event_key DESC,content_sha256 DESC LIMIT %d
SETTINGS max_threads=1,max_memory_usage=134217728,max_execution_time=5%s FORMAT JSONEachRow`, where, query.Limit+1, readBudget)
	data, err := s.query(ctx, sql)
	if err != nil {
		return StreamEventIndexPage{}, err
	}
	page := StreamEventIndexPage{Items: make([]StreamEventIndexItem, 0, query.Limit)}
	var lastHash string
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			ObservedAt string `json:"observed_at"`
			EventKey   string `json:"event_key"`
			Hash       string `json:"content_sha256"`
			Scope      string `json:"scope_id"`
			Protocol   string `json:"protocol"`
			EventType  string `json:"event_type"`
			Source     string `json:"source"`
			SensorID   string `json:"sensor_id"`
			SubjectIP  string `json:"subject_ip"`
			SubjectMAC string `json:"subject_mac"`
			SrcIP      string `json:"src_ip"`
			DstIP      string `json:"dst_ip"`
			SrcPort    uint32 `json:"src_port"`
			DstPort    uint32 `json:"dst_port"`
			Month      uint32 `json:"archive_month"`
			Class      string `json:"retention_class"`
			BodyRef    string `json:"body_ref"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return StreamEventIndexPage{}, err
		}
		observed, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.ObservedAt))
		if err != nil {
			return StreamEventIndexPage{}, err
		}
		ref, err := ParseStreamBodyRef(row.BodyRef)
		if err != nil {
			return StreamEventIndexPage{}, err
		}
		if row.Scope != query.ScopeID || (query.Protocol != "" && row.Protocol != query.Protocol) || observed.Before(query.From) || !observed.Before(query.To) ||
			(query.SubjectIP != "" && row.SubjectIP != query.SubjectIP) || (query.SensorID != "" && row.SensorID != query.SensorID) ||
			(query.Epoch != "" && !strings.HasPrefix(row.EventKey, query.Epoch+":")) || (query.ObservationOnly && !trafficObservationProtocol(row.Protocol)) ||
			ref.Scope != row.Scope || ref.Key != row.EventKey || ref.SHA256 != row.Hash || ref.Month != fmt.Sprint(row.Month) || ref.Class != row.Class {
			return StreamEventIndexPage{}, streamlog.ErrContentConflict
		}
		if len(page.Items) == query.Limit {
			break
		}
		page.Items = append(page.Items, StreamEventIndexItem{ObservedAt: observed, EventKey: row.EventKey, Protocol: row.Protocol,
			EventType: row.EventType, Source: row.Source, SensorID: row.SensorID, SubjectIP: row.SubjectIP,
			SubjectMAC: row.SubjectMAC, SrcIP: row.SrcIP, DstIP: row.DstIP, SrcPort: row.SrcPort, DstPort: row.DstPort, Body: ref})
		lastHash = row.Hash
	}
	if len(page.Items) == query.Limit && bytes.Count(bytes.TrimSpace(data), []byte{'\n'}) >= query.Limit {
		last := page.Items[len(page.Items)-1]
		raw, _ := json.Marshal(streamIndexCursor{Filter: streamIndexFilter(query), Observed: last.ObservedAt.UTC().Format(time.RFC3339Nano), Key: last.EventKey, Hash: lastHash})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}
