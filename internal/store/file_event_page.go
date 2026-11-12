package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"proxy-sentinel/internal/normalized"
)

type fileEventRow struct {
	key   eventKey
	event normalized.Event
}

func (s *FileStore) listEventCursorPage(ctx context.Context, query Query) (EventPage, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > maxEventPageSize {
		limit = maxEventPageSize
	}
	effective, cursor, err := prepareEventListQuery(query, time.Now())
	if err != nil {
		return EventPage{}, err
	}
	rows := make([]fileEventRow, 0, limit+1)
	err = s.visitFilteredEvents(ctx, effective, func(event normalized.Event) {
		key := eventKey{Timestamp: event.Timestamp, EventID: event.EventID, SensorID: stringFromMap(event.Observer, "sensor_id")}
		if cursor.After.Timestamp != "" && !eventKeyBefore(key, cursor.After) {
			return
		}
		at := 0
		for at < len(rows) && eventKeyBefore(key, rows[at].key) {
			at++
		}
		if at < len(rows) && rows[at].key == key || at > 0 && rows[at-1].key == key {
			return
		}
		if at > limit {
			return
		}
		rows = append(rows, fileEventRow{})
		copy(rows[at+1:], rows[at:])
		rows[at] = fileEventRow{key: key, event: event}
		if len(rows) > limit+1 {
			rows = rows[:limit+1]
		}
	})
	if err != nil {
		return EventPage{}, err
	}
	page := EventCursorPage{Limit: limit, HasMore: len(rows) > limit}
	if page.HasMore {
		rows = rows[:limit]
		page.NextCursor = encodeEventListCursor(cursor, rows[len(rows)-1].key)
	}
	events := make([]normalized.Event, len(rows))
	for i, row := range rows {
		events[i] = row.event
	}
	return EventPage{Items: events, Page: page}, nil
}

func (s *FileStore) CountEvents(ctx context.Context, query Query) (int, error) {
	count := 0
	err := s.visitFilteredEvents(ctx, query, func(normalized.Event) { count++ })
	return count, err
}

func (s *FileStore) visitFilteredEvents(ctx context.Context, query Query, visit func(normalized.Event)) error {
	from, err := optionalTime(query.From)
	if err != nil {
		return fmt.Errorf("bad from: %w", err)
	}
	to, err := optionalTime(query.To)
	if err != nil {
		return fmt.Errorf("bad to: %w", err)
	}
	if query.Window != "" && query.From == "" && query.To == "" {
		_, duration, err := NormalizeActivityWindow(query.Window)
		if err != nil {
			return err
		}
		to = time.Now()
		from = to.Add(-duration)
	}
	latest, ok, err := s.latestRun(ctx)
	if err != nil || !ok {
		return err
	}
	file, err := os.Open(filepath.Join(latest.Dir, "normalized.jsonl"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var event normalized.Event
		if json.Unmarshal(scanner.Bytes(), &event) != nil || !eventMatchesQuery(event, query, from, to) {
			continue
		}
		visit(event)
	}
	return scanner.Err()
}
