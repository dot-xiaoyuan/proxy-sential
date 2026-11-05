package store

import (
	"context"
	"errors"
	"fmt"
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
	for table := range tables {
		queued, err := s.streamSystemCount(ctx, "SELECT count() FROM system.asynchronous_inserts WHERE database=currentDatabase() AND table="+chQuote(table))
		if err != nil {
			return err
		}
		if queued != 0 {
			return streamlog.ErrUnconfirmed
		}
	}
	return s.ReconcileStreamBody(ctx, id, segment)
}

// RetryProvenUnsentStreamLane is an operator recovery path for a stopped
// source. It reuses the original immutable segment and deduplication token
// only when every expected row is absent, ClickHouse has no queued insert for
// the table, and recent query logging proves the original token was never
// received. A partial or ambiguous result stays on disk for investigation.
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
	from := segment.AcceptedAt.Add(-time.Minute).UTC().Format("2006-01-02 15:04:05")
	tables := []string{table}
	if rawRequired {
		tables = append([]string{"stream_source_raw"}, tables...)
	}
	for _, sink := range tables {
		queued, err := s.streamSystemCount(ctx, "SELECT count() FROM system.asynchronous_inserts WHERE database=currentDatabase() AND table="+chQuote(sink))
		if err != nil {
			return err
		}
		if queued != 0 {
			return streamlog.ErrUnconfirmed
		}
		token := streamInsertSettings(id, sink)["insert_deduplication_token"]
		received, err := s.streamSystemCount(ctx, "SELECT count() FROM system.query_log WHERE event_time >= toDateTime("+chQuote(from)+") AND Settings['insert_deduplication_token']="+chQuote(token))
		if err != nil {
			return err
		}
		if received != 0 {
			return streamlog.ErrUnconfirmed
		}
		coverage, err := s.streamSystemCount(ctx, "SELECT count() FROM system.query_log WHERE event_time >= toDateTime("+chQuote(from)+") AND query LIKE "+chQuote("INSERT INTO "+sink+"%"))
		if err != nil {
			return err
		}
		if coverage == 0 {
			return streamlog.ErrUnconfirmed
		}
	}
	if lane == streamlog.Archive {
		if err := s.WriteStreamBody(ctx, id, segment); err != nil {
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
	if err := s.WriteStreamSearch(ctx, id, segment); err != nil {
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
	queued, err := s.streamSystemCount(ctx, "SELECT count() FROM system.asynchronous_inserts WHERE database=currentDatabase() AND table="+chQuote(table))
	if err != nil || queued != 0 {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	from := segment.AcceptedAt.Add(-time.Minute).UTC().Format("2006-01-02 15:04:05")
	token := streamInsertSettings(id, table)["insert_deduplication_token"]
	received, err := s.streamSystemCount(ctx, "SELECT count() FROM system.query_log WHERE event_time >= toDateTime("+chQuote(from)+") AND Settings['insert_deduplication_token']="+chQuote(token))
	if err != nil || received != 0 {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	coverage, err := s.streamSystemCount(ctx, "SELECT count() FROM system.query_log WHERE event_time >= toDateTime("+chQuote(from)+") AND query LIKE 'INSERT INTO stream_risk_features_v1%'")
	if err != nil || coverage == 0 {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	if err := s.WriteStreamRiskFeatures(ctx, id, segment); err != nil {
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

func (s *ClickHouseStore) streamSystemCount(ctx context.Context, sql string) (int, error) {
	data, err := s.query(ctx, sql)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
