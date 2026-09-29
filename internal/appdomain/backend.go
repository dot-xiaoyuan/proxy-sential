package appdomain

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// DatabaseBackend is deliberately independent of collectors and risk processing.
// Each Step owns at most one bounded batch; implementations persist their leases.
type DatabaseBackend interface {
	State(context.Context) (ProcessingStatus, error)
	Start(context.Context, time.Time, string) error
	Control(context.Context, string) error
	Step(context.Context, string, time.Time, *Bundle) (bool, error)
	Report(context.Context, Query) (Report, error)
	Page(context.Context, Query, PageRequest) (ObservationPage, error)
	Export(context.Context, Query, io.Writer) error
}
type DatabaseProvider interface{ ApplicationBackend() DatabaseBackend }
type ProcessingStatus struct {
	Realtime    Job    `json:"realtime"`
	History     Job    `json:"history"`
	Reconcile   Job    `json:"reconcile"`
	Storage     string `json:"storage"`
	QueryMillis int64  `json:"query_millis"`
}
type PageRequest struct {
	Limit, Offset int
	Cursor        string
}
type ObservationPage struct {
	Items      []Observation `json:"items"`
	Total      int           `json:"total"`
	TotalAsOf  string        `json:"total_as_of,omitempty"`
	Limit      int           `json:"limit"`
	Offset     int           `json:"offset"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

func EncodePageCursor(o Observation) string {
	b, _ := json.Marshal(Cursor{Timestamp: o.Timestamp, SensorID: o.SensorID, EventID: o.EventID})
	return base64.RawURLEncoding.EncodeToString(b)
}
func DecodePageCursor(raw string) (Cursor, error) {
	var c Cursor
	if raw == "" {
		return c, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, fmt.Errorf("invalid cursor")
	}
	if json.Unmarshal(b, &c) != nil || c.EventID == "" {
		return c, fmt.Errorf("invalid cursor")
	}
	if _, err = time.Parse(time.RFC3339Nano, c.Timestamp); err != nil {
		return c, fmt.Errorf("invalid cursor timestamp")
	}
	return c, nil
}
func (s *Service) Report(ctx context.Context, q Query) (Report, error) {
	if s.backend != nil {
		return s.backend.Report(ctx, q)
	}
	return Aggregate(s.Snapshot(), q), nil
}
func (s *Service) Page(ctx context.Context, q Query, p PageRequest) (ObservationPage, error) {
	if s.backend != nil {
		return s.backend.Page(ctx, q, p)
	}
	c, err := DecodePageCursor(p.Cursor)
	if err != nil {
		return ObservationPage{}, err
	}
	items := []Observation{}
	total := 0
	for _, o := range s.Snapshot() {
		if !eligible(o, q) || q.ApplicationID != "" && (o.Match.TargetType != "application" || o.Match.TargetID != q.ApplicationID) {
			continue
		}
		total++
		if p.Cursor != "" && (o.Timestamp > c.Timestamp || o.Timestamp == c.Timestamp && o.Key() <= c.SensorID+"\x00"+c.EventID) {
			continue
		}
		items = append(items, o)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Timestamp != items[j].Timestamp {
			return items[i].Timestamp > items[j].Timestamp
		}
		return items[i].Key() < items[j].Key()
	})
	offset := p.Offset
	if offset > len(items) {
		offset = len(items)
	}
	items = items[offset:]
	next := ""
	if len(items) > p.Limit {
		items = items[:p.Limit]
		next = EncodePageCursor(items[len(items)-1])
	}
	return ObservationPage{Items: items, Total: total, Limit: p.Limit, Offset: p.Offset, NextCursor: next}, nil
}
func (s *Service) Export(ctx context.Context, q Query, w io.Writer) error {
	if s.backend != nil {
		return s.backend.Export(ctx, q, w)
	}
	enc := json.NewEncoder(w)
	for _, row := range UnknownDomains(s.Snapshot(), q) {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Processing(ctx context.Context) (ProcessingStatus, error) {
	if s.backend != nil {
		return s.backend.State(ctx)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ProcessingStatus{Storage: "file", Realtime: s.state.Scan, History: s.state.Job}, nil
}
