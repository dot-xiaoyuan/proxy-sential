package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/normalized"
)

const (
	identityDerivedBatchMaxFragments = 16
	identityDerivedBatchMaxRecords   = 200
	identityDerivedBatchMaxBytes     = 1 << 20
)

type identityDerivedBatchBudget struct{ Records, Bytes int }

var errIdentityDerivedBatchFull = errors.New("identity derived batch budget exhausted")
var errIdentityDerivedReadyIneligible = errors.New("identity derived ready key is not eligible")

// Lease at most 16 fragments in one commit. Inspect only the next fragment's
// size before reading its body; leave it untouched if either budget is full.
// All selected epochs commit together, or all are rolled back on SQL failure.
func (s *PostgresStore) claimIdentityDerivedReadyBatch(ctx context.Context, priority int) ([]identityExportFragment, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	budget := identityDerivedBatchBudget{identityDerivedBatchMaxRecords, identityDerivedBatchMaxBytes}
	fragments := []identityExportFragment{}
	deferred := false
	for tries := 0; tries < 32 && len(fragments) < identityDerivedBatchMaxFragments && budget.Records > 0 && budget.Bytes > 0; tries++ {
		fragment, claimErr := s.claimIdentityDerivedReadyTx(ctx, tx, priority, &budget)
		if errors.Is(claimErr, errIdentityDerivedBatchFull) && len(fragments) == 0 {
			return nil, fmt.Errorf("first ready fragment exceeds batch bounds: %w", claimErr)
		}
		if errors.Is(claimErr, sql.ErrNoRows) || errors.Is(claimErr, errIdentityDerivedBatchFull) {
			break
		}
		if errors.Is(claimErr, errIdentityDerivedReadyDeferred) || errors.Is(claimErr, errIdentityDerivedReadyIneligible) {
			deferred = true
			continue
		}
		if claimErr != nil {
			return nil, claimErr
		}
		if fragment.Count > budget.Records || len(fragment.Payload) > budget.Bytes {
			return nil, errors.New("identity derived claim exceeded batch budget")
		}
		fragments = append(fragments, fragment)
		budget.Records -= fragment.Count
		budget.Bytes -= len(fragment.Payload)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if len(fragments) == 0 {
		if deferred {
			return nil, errIdentityDerivedReadyDeferred
		}
		return nil, sql.ErrNoRows
	}
	return fragments, nil
}

func (s *DBStore) projectIdentityDerivedReadyBatch(ctx context.Context, priority int) error {
	started := time.Now()
	fragments, err := s.pg.claimIdentityDerivedReadyBatch(ctx, priority)
	if errors.Is(err, sql.ErrNoRows) {
		fragments, err = s.pg.claimIdentityDerivedReadyBatch(ctx, 1-priority)
	}
	if err != nil {
		return err
	}
	claimedAt := time.Now()
	events := []normalized.Event{}
	valid := []identityExportFragment{}
	eventIDs := [][]string{}
	var invalidErr error
	for _, fragment := range fragments {
		segment, _, decodeErr := identityFragmentSegment(fragment)
		if decodeErr != nil {
			report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			reportErr := s.pg.reportIdentityDerivedFragmentError(report, fragment, decodeErr)
			cancel()
			invalidErr = errors.Join(invalidErr, decodeErr, reportErr)
			continue
		}
		valid = append(valid, fragment)
		events = append(events, segment.Events...)
		ids := make([]string, 0, len(segment.Events))
		for _, e := range segment.Events {
			ids = append(ids, e.EventID)
		}
		eventIDs = append(eventIDs, ids)
	}
	if len(valid) == 0 {
		return invalidErr
	}
	err = s.applyIdentityDerivedFragments(ctx, valid, events)
	completed := time.Now()
	for i, fragment := range valid {
		if err != nil {
			report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			reportErr := s.pg.reportIdentityDerivedFragmentError(report, fragment, err)
			cancel()
			if reportErr != nil {
				fmt.Fprintln(os.Stderr, "identity derived report:", reportErr)
			}
		}
		overdue := []string{}
		if completed.Sub(fragment.Accepted) > 5*time.Second {
			overdue = eventIDs[i]
		}
		metric := map[string]any{"metric": "identity_derived_queryable", "sensor": s.pg.sensorID, "batch_id": fragment.BatchID, "offset": fragment.First, "records": fragment.Count, "accepted_at": fragment.Accepted, "completed_at": completed, "latency_ms": completed.Sub(fragment.Accepted).Milliseconds(), "claim_ms": claimedAt.Sub(started).Milliseconds(), "apply_ms": completed.Sub(claimedAt).Milliseconds(), "group_fragments": len(valid), "group_records": len(events), "failed": err != nil, "overdue_event_ids": overdue}
		if err == nil {
			metric["queryable_at"] = completed
		}
		raw, _ := json.Marshal(metric)
		fmt.Fprintln(os.Stderr, string(raw))
	}
	return errors.Join(err, invalidErr)
}
