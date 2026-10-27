package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type streamRouterCursor struct {
	IndexedAt time.Time
	EventKey  string
	Owner     string
}

var ErrStreamRouterIndexGap = errors.New("stream router cursor is older than retained index coverage")

func (s *DBStore) claimStreamRouterRecognition(ctx context.Context, sensor, owner string) (streamRouterCursor, bool, error) {
	if sensor == "" || owner == "" {
		return streamRouterCursor{}, false, errors.New("stream router claim requires sensor and owner")
	}
	version := fingerprint.DefaultRouterRuleSet().Version
	var stamp sql.NullTime
	var key string
	err := s.pg.db.QueryRowContext(ctx, `UPDATE stream_router_recognition_state SET
 lease_owner=$2,lease_until=now()+interval '90 seconds',updated_at=now()
 WHERE sensor_id=$1 AND lease_until<now() AND fresh_cutoff_at IS NOT NULL AND rule_version=$3
 RETURNING cursor_indexed_at,cursor_event_key`, sensor, owner, version).Scan(&stamp, &key)
	if errors.Is(err, sql.ErrNoRows) {
		var priorVersion string
		if queryErr := s.pg.db.QueryRowContext(ctx, `SELECT rule_version FROM stream_router_recognition_state WHERE sensor_id=$1`, sensor).Scan(&priorVersion); queryErr == nil && priorVersion != version {
			return streamRouterCursor{}, false, errors.New("stream router rule changed; new audited fresh cutover is required")
		} else if queryErr != nil && !errors.Is(queryErr, sql.ErrNoRows) {
			return streamRouterCursor{}, false, queryErr
		}
		return streamRouterCursor{}, false, nil
	}
	if err != nil {
		return streamRouterCursor{}, false, err
	}
	return streamRouterCursor{IndexedAt: stamp.Time.UTC(), EventKey: key, Owner: owner}, true, nil
}

func (s *DBStore) finishStreamRouterRecognition(ctx context.Context, sensor string, next streamRouterCursor, processed int, runErr error) error {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var stamp any
	if !next.IndexedAt.IsZero() {
		stamp = next.IndexedAt
	}
	message := ""
	if runErr != nil {
		message = runErr.Error()
	}
	result, err := s.pg.db.ExecContext(finishCtx, `UPDATE stream_router_recognition_state SET
 cursor_indexed_at=CASE WHEN $4::boolean THEN COALESCE($3,cursor_indexed_at) ELSE cursor_indexed_at END,
 cursor_event_key=CASE WHEN $4::boolean AND $3::timestamptz IS NOT NULL THEN $5 ELSE cursor_event_key END,
 processed_events=processed_events+CASE WHEN $4::boolean THEN $6 ELSE 0 END,
 last_success_at=CASE WHEN $4::boolean THEN now() ELSE last_success_at END,
 last_error=$7,lease_owner='',lease_until='-infinity',updated_at=now()
 WHERE sensor_id=$1 AND lease_owner=$2 AND lease_until>now()`, sensor, next.Owner, stamp, runErr == nil, next.EventKey, processed, message)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errRecognitionLeaseLost
	}
	return nil
}

func (s *DBStore) streamRouterSignalBatch(ctx context.Context, sensor string, cursor streamRouterCursor) ([]normalized.Event, streamRouterCursor, error) {
	if !cursor.IndexedAt.IsZero() && time.Since(cursor.IndexedAt) > 7*24*time.Hour {
		return nil, cursor, ErrStreamRouterIndexGap
	}
	indexed, err := s.ch.ListStreamRouterSignalRefs(ctx, sensor, cursor.IndexedAt, cursor.EventKey, 100)
	if err != nil || len(indexed) == 0 {
		return nil, cursor, err
	}
	refs := make([]StreamBodyRef, 0, len(indexed))
	unique := make([]StreamRouterSignalRef, 0, len(indexed))
	for _, item := range indexed {
		if len(unique) > 0 && item.IndexedAt.Equal(unique[len(unique)-1].IndexedAt) && item.EventKey == unique[len(unique)-1].EventKey {
			if item.Body != unique[len(unique)-1].Body || !item.ObservedAt.Equal(unique[len(unique)-1].ObservedAt) {
				return nil, cursor, streamlog.ErrContentConflict
			}
			continue
		}
		refs = append(refs, item.Body)
		unique = append(unique, item)
	}
	bodies, err := s.ch.GetStreamEventsByRefs(ctx, refs)
	if err != nil {
		return nil, cursor, err
	}
	events := make([]normalized.Event, 0, len(unique))
	for _, item := range unique {
		event := bodies[item.Body]
		observed, parseErr := time.Parse(time.RFC3339Nano, event.Timestamp)
		if parseErr != nil || streamScope(event) != item.Body.Scope || stringFromMap(event.Observer, "sensor_id") != sensor || event.SourceEventType != item.Protocol ||
			(event.Type != "device" && event.Type != "router") || !observed.UTC().Truncate(time.Microsecond).Equal(item.ObservedAt) {
			return nil, cursor, streamlog.ErrContentConflict
		}
		events = append(events, event)
	}
	last := unique[len(unique)-1]
	return events, streamRouterCursor{IndexedAt: last.IndexedAt, EventKey: last.EventKey, Owner: cursor.Owner}, nil
}

func (s *DBStore) runStreamRouterRecognitionMaterializer(ctx context.Context, sensor string) {
	owner := fmt.Sprintf("stream-router-%d-%d", os.Getpid(), time.Now().UnixNano())
	for ctx.Err() == nil {
		started := time.Now()
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		cursor, claimed, err := s.claimStreamRouterRecognition(workCtx, sensor, owner)
		claimDuration := time.Since(started)
		processed := 0
		var readDuration, analyzeDuration, expiryDuration, finishDuration time.Duration
		if err == nil && claimed {
			var events []normalized.Event
			var next streamRouterCursor
			stage := time.Now()
			events, next, err = s.streamRouterSignalBatch(workCtx, sensor, cursor)
			readDuration = time.Since(stage)
			if err == nil && len(events) > 0 {
				stage = time.Now()
				err = s.analyzeAndWriteStreamRouterEvents(workCtx, events)
				analyzeDuration = time.Since(stage)
			}
			if err == nil {
				stage = time.Now()
				_, err = s.pg.refreshExpiredRouterAssessments(workCtx, 50)
				expiryDuration = time.Since(stage)
			}
			if err == nil {
				cursor, processed = next, len(events)
			}
			stage = time.Now()
			if finishErr := s.finishStreamRouterRecognition(ctx, sensor, cursor, processed, err); err == nil {
				err = finishErr
			}
			finishDuration = time.Since(stage)
			if total := time.Since(started); total >= 2*time.Second {
				fmt.Fprintf(os.Stderr, "stream router batch events=%d total_ms=%d claim_ms=%d read_ms=%d analyze_ms=%d expiry_ms=%d finish_ms=%d\n",
					processed, total.Milliseconds(), claimDuration.Milliseconds(), readDuration.Milliseconds(),
					analyzeDuration.Milliseconds(), expiryDuration.Milliseconds(), finishDuration.Milliseconds())
			}
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "stream router recognition failed: %v\n", err)
		}
		if claimed && err == nil && processed > 0 {
			// Each bounded batch already waits for both stores and a durable
			// cursor. An extra one-second pause caps this lane below the live
			// index rate even when all storage calls are instantaneous.
			continue
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
