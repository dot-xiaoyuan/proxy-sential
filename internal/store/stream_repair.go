package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// ReconcileSettledStreamBody repairs an old ambiguous archive attempt after
// its source has been stopped and leased by the operator. A scoped read keeps
// already archived rows untouched; a non-empty async queue leaves the attempt
// unconfirmed instead of racing a delayed ClickHouse flush.
func (s *ClickHouseStore) ReconcileSettledStreamBody(ctx context.Context, id string, segment streamlog.Segment) error {
	if id == "" || !segment.SourceBackedRaw || len(segment.Raw) == 0 || len(segment.Events) == 0 ||
		segment.AcceptedAt.IsZero() || time.Since(segment.AcceptedAt) < time.Hour {
		return fmt.Errorf("settled source-backed archive proof is incomplete: %w", streamlog.ErrUnconfirmed)
	}
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return err
	}
	tables := map[string]bool{"stream_source_raw": true}
	for _, item := range prepared {
		tables[streamBodyTable(item.retention, segment.BodyLayout)] = true
	}
	if err := s.requireQuietStreamRepair(ctx, sortedStreamRepairTables(tables)); err != nil {
		return err
	}
	return s.ReconcileStreamBody(ctx, id, segment)
}

// RetryProvenUnsentStreamLane is an operator recovery path for a source held by
// the journal lease. It checks every expected key and hash in the immutable
// segment and requires quiet ClickHouse insert queues before a distinct repair
// token. A partial or conflicting result stays on disk for investigation.
// The original insert's arrival cannot be proven from diagnostic query logs.
func (s *ClickHouseStore) RetryProvenUnsentStreamLane(ctx context.Context, id string, segment streamlog.Segment, lane streamlog.Lane) error {
	age := time.Since(segment.AcceptedAt)
	if age < 2*time.Minute || age > time.Hour {
		return fmt.Errorf("stream repair requires a recent, settled attempt: %w", streamlog.ErrUnconfirmed)
	}
	var table string
	var missing []int
	var err error
	switch lane {
	case streamlog.Archive:
		prepared, prepErr := prepareStreamEvents(segment)
		if prepErr != nil {
			return prepErr
		}
		if len(prepared) == 0 {
			return fmt.Errorf("empty archive segment cannot be repaired: %w", streamlog.ErrUnconfirmed)
		}
		for _, item := range prepared {
			if item.retention != prepared[0].retention {
				return errors.New("mixed retention classes require separate repair proof")
			}
		}
		table = streamBodyTable(prepared[0].retention, segment.BodyLayout)
		missing, err = s.missingStreamBodyEvents(ctx, segment)
	case streamlog.Search:
		table = "stream_event_search"
		missing, err = s.missingStreamSearchEvents(ctx, segment)
	default:
		return errors.New("only ClickHouse lanes can be repaired")
	}
	if err != nil {
		return err
	}
	rawRequired := lane == streamlog.Archive && streamRawArchiveRequired(segment)
	if rawRequired {
		present, verifyErr := s.verifyStreamRaw(ctx, id, segment)
		if verifyErr != nil {
			return verifyErr
		}
		if present != (len(missing) == 0) {
			return fmt.Errorf("partial source and body archive requires scoped manual review: %w", streamlog.ErrUnconfirmed)
		}
	}
	if len(missing) == 0 {
		if lane == streamlog.Search && segment.RiskFeaturesRequired {
			confirmed, verifyErr := s.VerifyStreamRiskFeatures(ctx, segment)
			if verifyErr != nil || !confirmed {
				if verifyErr != nil {
					return verifyErr
				}
				return fmt.Errorf("risk features require separate repair: %w", streamlog.ErrUnconfirmed)
			}
		}
		return nil
	}
	if len(missing) != len(segment.Events) {
		return fmt.Errorf("partially committed stream segment requires scoped manual review: %w", streamlog.ErrUnconfirmed)
	}
	tables := []string{table}
	if rawRequired {
		tables = append([]string{"stream_source_raw"}, tables...)
	}
	if err := s.requireQuietStreamRepair(ctx, tables); err != nil {
		return err
	}
	// An old asynchronous insert can finish while we establish the quiet
	// interval. Recheck immutable keys after the interval and before minting a
	// distinct repair token; any arrival leaves this attempt for manual review.
	if lane == streamlog.Archive {
		missing, err = s.missingStreamBodyEvents(ctx, segment)
	} else {
		missing, err = s.missingStreamSearchEvents(ctx, segment)
	}
	if err != nil {
		return err
	}
	if len(missing) != len(segment.Events) {
		return streamlog.ErrUnconfirmed
	}
	if rawRequired {
		present, err := s.verifyStreamRaw(ctx, id, segment)
		if err != nil || present {
			if err != nil {
				return err
			}
			return streamlog.ErrUnconfirmed
		}
	}
	if lane == streamlog.Archive {
		if err := s.ReconcileStreamBody(ctx, id, segment); err != nil {
			return err
		}
		if rawRequired {
			confirmed, err := s.verifyStreamRaw(ctx, id, segment)
			if err != nil || !confirmed {
				if err != nil {
					return err
				}
				return streamlog.ErrUnconfirmed
			}
		}
		confirmed, err := s.VerifyStreamBody(ctx, segment)
		if err != nil || !confirmed {
			if err != nil {
				return err
			}
			return streamlog.ErrUnconfirmed
		}
		return nil
	}
	if err := s.ReconcileStreamSearch(ctx, id, segment); err != nil {
		return err
	}
	confirmed, err := s.VerifyStreamSearch(ctx, segment)
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	if !segment.RiskFeaturesRequired {
		return nil
	}
	confirmed, err = s.VerifyStreamRiskFeatures(ctx, segment)
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return fmt.Errorf("risk features require separate repair: %w", streamlog.ErrUnconfirmed)
	}
	return nil
}

// RetryProvenUnsentStreamRiskFeatures repairs only the compact risk feature
// sink of an attempted search lane. Search and body must already be confirmed.
func (s *ClickHouseStore) RetryProvenUnsentStreamRiskFeatures(ctx context.Context, id string, segment streamlog.Segment) error {
	if !segment.RiskFeaturesRequired {
		return errors.New("segment has no risk-feature acknowledgement requirement")
	}
	age := time.Since(segment.AcceptedAt)
	if age < 2*time.Minute || age > time.Hour {
		return streamlog.ErrUnconfirmed
	}
	search, err := s.VerifyStreamSearch(ctx, segment)
	if err != nil || !search {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil || len(features) == 0 {
		return err
	}
	missing, err := s.missingStreamRiskFeatures(ctx, segment)
	if err != nil || len(missing) == 0 {
		return err
	}
	if len(missing) != len(features) {
		return fmt.Errorf("partially committed risk feature segment requires scoped manual review: %w", streamlog.ErrUnconfirmed)
	}
	const table = "stream_risk_features_v1"
	if err := s.requireQuietStreamRepair(ctx, []string{table}); err != nil {
		return err
	}
	missing, err = s.missingStreamRiskFeatures(ctx, segment)
	if err != nil {
		return err
	}
	if len(missing) != len(features) {
		return streamlog.ErrUnconfirmed
	}
	if err := s.WriteStreamRiskFeatures(ctx, streamRepairToken(id, table), segment); err != nil {
		return err
	}
	confirmed, err := s.VerifyStreamRiskFeatures(ctx, segment)
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	return nil
}

func streamRepairToken(segmentID, table string) string {
	return fmt.Sprintf("repair:%s:%s:%d", segmentID, table, time.Now().UTC().UnixNano())
}

const streamRepairQuietInterval = 500 * time.Millisecond

func sortedStreamRepairTables(tables map[string]bool) []string {
	result := make([]string, 0, len(tables))
	for table := range tables {
		result = append(result, table)
	}
	sort.Strings(result)
	return result
}

// requireQuietStreamRepair is only called with a stopped source lease held by
// the operator command. The two checks include queued async inserts and active
// INSERT requests; no diagnostic query-log retention is needed.
func (s *ClickHouseStore) requireQuietStreamRepair(ctx context.Context, tables []string) error {
	for check := 0; check < 2; check++ {
		for _, table := range tables {
			queued, err := s.streamSystemCount(ctx, "SELECT count() FROM system.asynchronous_inserts WHERE database=currentDatabase() AND table="+chQuote(table))
			if err != nil {
				return err
			}
			if queued != 0 {
				return streamlog.ErrUnconfirmed
			}
			active, err := s.streamSystemCount(ctx, "SELECT count() FROM system.processes WHERE current_database=currentDatabase() AND lower(query_kind)='insert' AND positionCaseInsensitive(query,"+chQuote(table)+")>0")
			if err != nil {
				return err
			}
			if active != 0 {
				return streamlog.ErrUnconfirmed
			}
		}
		if check == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(streamRepairQuietInterval):
			}
		}
	}
	return nil
}

func (s *ClickHouseStore) streamSystemCount(ctx context.Context, sql string) (int, error) {
	data, err := s.query(ctx, sql)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
