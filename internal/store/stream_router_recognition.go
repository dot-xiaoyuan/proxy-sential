package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

type streamRouterCursor struct {
	IndexedAt time.Time
	EventKey  string
	Owner     string
}

const maxRouterWeakBatchesPerClaim = 5

type streamRouterBatchRead func(context.Context, streamRouterCursor) ([]normalized.Event, streamRouterCursor, error)

// A claim can advance across a bounded run of pure packet TTL rows without
// writing a PostgreSQL lease and cursor for every 100 weak observations.
// Any failure returns the original cursor, so the next owner replays the run.
func runStreamRouterClaimBatches(ctx context.Context, start streamRouterCursor, read streamRouterBatchRead, analyze func(context.Context, []normalized.Event) error) (streamRouterCursor, int, int, time.Duration, time.Duration, error) {
	cursor := start
	processed, weak := 0, 0
	var readDuration, analyzeDuration time.Duration
	started := time.Now()
	for batch := 0; batch < maxRouterWeakBatchesPerClaim; batch++ {
		stage := time.Now()
		events, next, err := read(ctx, cursor)
		readDuration += time.Since(stage)
		if err != nil {
			return start, 0, 0, readDuration, analyzeDuration, err
		}
		if len(events) == 0 {
			break
		}
		scoring, excluded := routerScoringEvents(events)
		if len(scoring) > 0 {
			stage = time.Now()
			if err := analyze(ctx, events); err != nil {
				analyzeDuration += time.Since(stage)
				return start, 0, 0, readDuration, analyzeDuration, err
			}
			analyzeDuration += time.Since(stage)
		}
		cursor, processed, weak = next, processed+len(events), weak+excluded
		// A scored batch ends the claim. Earlier batches only contained weak TTL,
		// so replay after a failed scoring write cannot duplicate scored work.
		if len(scoring) > 0 || time.Since(started) >= 10*time.Second {
			break
		}
	}
	return cursor, processed, weak, readDuration, analyzeDuration, nil
}

var ErrStreamRouterIndexGap = errors.New("stream router cursor is older than retained index coverage")

// The shortest router index TTL is toDateTime(indexed_at)+6 days (CH 055).
// toDateTime truncates microseconds, so stop at that whole-second boundary
// even if the physical TTL merge has not yet removed the row.
func streamRouterIndexExpired(now, indexedAt time.Time) bool {
	return !indexedAt.IsZero() && !now.Before(indexedAt.UTC().Truncate(time.Second).Add(6*24*time.Hour))
}

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
	// The cursor write is a small transaction, but on 184 it can wait behind
	// PostgreSQL WAL flushes for more than five seconds. Keep it bounded well
	// inside the 90-second lease so a successful scoring batch is not replayed.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
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
	if streamRouterIndexExpired(time.Now().UTC(), cursor.IndexedAt) {
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
			prior := unique[len(unique)-1]
			if item.Body != prior.Body {
				return nil, cursor, streamPositionConflict("router.duplicate_index", "body_ref_mismatch", item.IndexedAt, prior.Body, item.EventKey, item.Body.SHA256)
			}
			if !item.ObservedAt.Equal(prior.ObservedAt) {
				return nil, cursor, streamPositionConflict("router.duplicate_index", "observed_at_mismatch", item.IndexedAt, prior.Body, item.EventKey, item.Body.SHA256, "same_observed_at", "different_observed_at")
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
		if parseErr != nil {
			return nil, cursor, streamPositionConflict("router.body_semantics", "timestamp_invalid", item.IndexedAt, item.Body, "", "", "rfc3339_timestamp", "invalid_timestamp")
		}
		if streamScope(event) != item.Body.Scope {
			return nil, cursor, streamPositionConflict("router.body_semantics", "scope_mismatch", item.IndexedAt, item.Body, "", "", "same_scope", "different_scope")
		}
		if stringFromMap(event.Observer, "sensor_id") != sensor {
			return nil, cursor, streamPositionConflict("router.body_semantics", "sensor_mismatch", item.IndexedAt, item.Body, "", "", "same_sensor", "different_sensor")
		}
		if event.SourceEventType != item.Protocol {
			return nil, cursor, streamPositionConflict("router.body_semantics", "protocol_mismatch", item.IndexedAt, item.Body, "", "", item.Protocol, event.SourceEventType)
		}
		if event.Type != "device" && event.Type != "router" {
			return nil, cursor, streamPositionConflict("router.body_semantics", "event_type_mismatch", item.IndexedAt, item.Body, "", "", "device_or_router", event.Type)
		}
		if !observed.UTC().Truncate(time.Microsecond).Equal(item.ObservedAt) {
			return nil, cursor, streamPositionConflict("router.body_semantics", "observed_at_mismatch", item.IndexedAt, item.Body, "", "", "same_observed_at", "different_observed_at")
		}
		events = append(events, event)
	}
	last := unique[len(unique)-1]
	return events, streamRouterCursor{IndexedAt: last.IndexedAt, EventKey: last.EventKey, Owner: cursor.Owner}, nil
}

func (s *DBStore) runStreamRouterRecognitionMaterializer(ctx context.Context, sensor string) {
	if os.Getenv("PROXY_SENTINEL_STREAM_ROUTER_DISABLED") == "true" {
		fmt.Fprintln(os.Stderr, "stream router recognition disabled by operator")
		return
	}
	claimBudget, budgetErr := parseStreamRouterClaimBudget(os.Getenv("PROXY_SENTINEL_STREAM_ROUTER_CLAIM_BUDGET"))
	if budgetErr != nil {
		fmt.Fprintf(os.Stderr, "stream router recognition disabled: %v\n", budgetErr)
		return
	}
	claims := 0
	owner := fmt.Sprintf("stream-router-%d-%d", os.Getpid(), time.Now().UnixNano())
	for ctx.Err() == nil {
		started := time.Now()
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		cursor, claimed, err := s.claimStreamRouterRecognition(workCtx, sensor, owner)
		if claimed {
			claims++
		}
		claimDuration := time.Since(started)
		processed := 0
		var readDuration, analyzeDuration, expiryDuration, finishDuration time.Duration
		if err == nil && claimed {
			var next streamRouterCursor
			var weak int
			next, processed, weak, readDuration, analyzeDuration, err = runStreamRouterClaimBatches(workCtx, cursor,
				func(ctx context.Context, at streamRouterCursor) ([]normalized.Event, streamRouterCursor, error) {
					return s.streamRouterSignalBatch(ctx, sensor, at)
				}, s.analyzeAndWriteStreamRouterEvents)
			if err == nil {
				stage := time.Now()
				_, err = s.pg.refreshExpiredRouterAssessments(workCtx, 50)
				expiryDuration = time.Since(stage)
			}
			if err == nil {
				cursor = next
			} else {
				processed = 0
			}
			stage := time.Now()
			if finishErr := s.finishStreamRouterRecognition(ctx, sensor, cursor, processed, err); err == nil {
				err = finishErr
			}
			finishDuration = time.Since(stage)
			if total := time.Since(started); total >= 2*time.Second {
				fmt.Fprintf(os.Stderr, "stream router batch events=%d weak_ttl_excluded=%d total_ms=%d claim_ms=%d read_ms=%d analyze_ms=%d expiry_ms=%d finish_ms=%d\n",
					processed, weak, total.Milliseconds(), claimDuration.Milliseconds(), readDuration.Milliseconds(),
					analyzeDuration.Milliseconds(), expiryDuration.Milliseconds(), finishDuration.Milliseconds())
			}
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "stream router recognition failed: %v\n", err)
		}
		if claimBudget > 0 && claims >= claimBudget {
			fmt.Fprintf(os.Stderr, "stream router recognition claim budget reached: claims=%d\n", claims)
			return
		}
		timer := time.NewTimer(streamRouterClaimDelay(claimed, processed, err))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func parseStreamRouterClaimBudget(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 1000000 {
		return 0, fmt.Errorf("invalid PROXY_SENTINEL_STREAM_ROUTER_CLAIM_BUDGET %q", raw)
	}
	return value, nil
}

func streamRouterClaimDelay(claimed bool, processed int, runErr error) time.Duration {
	if claimed && runErr == nil && processed > 0 {
		// Bounded claims still need a pause after a successful cursor commit.
		return time.Second
	}
	return 5 * time.Second
}
