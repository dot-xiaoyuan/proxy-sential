package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// ReconcileSettledStreamBody repairs an old ambiguous archive attempt after
// its source has been stopped and leased by the operator. A scoped read keeps
// already archived rows untouched; a non-empty async queue leaves the attempt
// unconfirmed instead of racing a delayed ClickHouse flush. Device-signal
// standard-event raw lives in the immutable journal, not stream_source_raw.
func (s *ClickHouseStore) ReconcileSettledStreamBody(ctx context.Context, id string, segment streamlog.Segment) error {
	passiveJournal := false
	if segment.Source == "passive-discovery" {
		if err := verifySettledPassiveSegment(id, segment); err != nil {
			return err
		}
		passiveJournal = true
	}
	standardRaw := segment.RawIsStandardEvents && !segment.SourceBackedRaw &&
		(segment.Source == "device-signals" || segment.Source == "shared-device-signals") &&
		segment.EndOffset-segment.StartOffset == int64(len(segment.Raw))
	if standardRaw {
		sum := sha256.Sum256(segment.Raw)
		standardRaw = segment.RawSHA256 == hex.EncodeToString(sum[:])
	}
	if id == "" || (!segment.SourceBackedRaw && !standardRaw && !passiveJournal) || (!passiveJournal && len(segment.Raw) == 0) || len(segment.Events) == 0 ||
		segment.AcceptedAt.IsZero() || time.Since(segment.AcceptedAt) < time.Hour {
		return fmt.Errorf("settled source archive proof is incomplete: %w", streamlog.ErrUnconfirmed)
	}
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return err
	}
	tables := map[string]bool{}
	if streamRawArchiveRequired(segment) {
		tables["stream_source_raw"] = true
	}
	for _, item := range prepared {
		tables[streamBodyTable(item.retention, segment.BodyLayout)] = true
	}
	if err := s.requireQuietStreamRepair(ctx, sortedStreamRepairTables(tables)); err != nil {
		return err
	}
	return s.ReconcileStreamBody(ctx, id, segment)
}

// ReconcileSettledStreamSearch is limited to birth-aware standard-event
// sources whose body is already confirmed. The split risk-feature lane remains
// independently pending and is never acknowledged by repairing search rows.
func (s *ClickHouseStore) ReconcileSettledStreamSearch(ctx context.Context, id string, segment streamlog.Segment) error {
	if id == "" || segment.AcceptedAt.IsZero() || time.Since(segment.AcceptedAt) < time.Hour ||
		!birthAwareStandardEventRaw(segment) || segment.RiskFeaturesRequired && !segment.SplitRiskFeatures {
		return fmt.Errorf("settled search proof is incomplete: %w", streamlog.ErrUnconfirmed)
	}
	if _, err := prepareStreamEvents(segment); err != nil {
		return err
	}
	body, err := s.VerifyStreamBody(ctx, segment)
	if err != nil {
		return err
	}
	if !body {
		return fmt.Errorf("settled search requires confirmed body: %w", streamlog.ErrUnconfirmed)
	}
	confirmed, err := s.VerifyStreamSearch(ctx, segment)
	if err != nil || confirmed {
		return err
	}
	if err := s.requireQuietStreamRepair(ctx, []string{"stream_event_search"}); err != nil {
		return err
	}
	// A late insert can arrive during the quiet interval. The scoped repair
	// rechecks all immutable keys immediately before any distinct write token.
	return s.ReconcileStreamSearch(ctx, id, segment)
}

func birthAwareStandardEventRaw(segment streamlog.Segment) bool {
	if !segment.RawIsStandardEvents || segment.SourceBackedRaw ||
		segment.Source != "device-signals" && segment.Source != "shared-device-signals" ||
		!strings.Contains(segment.FileID, ":birth:") || len(segment.Raw) == 0 || len(segment.Events) == 0 ||
		segment.EndOffset-segment.StartOffset != int64(len(segment.Raw)) {
		return false
	}
	sum := sha256.Sum256(segment.Raw)
	return segment.RawSHA256 == hex.EncodeToString(sum[:])
}

// Passive capture has no retained packet bytes. Its immutable journal segment
// is the evidence for this lane. The operator CLI first loads and hashes that
// segment under the source lease; this second proof ties every event to the
// fixed journal interval and the stream3 key scheme before a scoped CH write.
func verifySettledPassiveSegment(id string, segment streamlog.Segment) error {
	if id == "" || id != streamlog.SourceSegmentID(segment) ||
		segment.ParserVersion != "passive-frame-v1" || !strings.HasPrefix(segment.SourcePath, "packet://") ||
		segment.FileID == "" || segment.PreviousFileID != segment.FileID || segment.PreviousOffset != segment.StartOffset ||
		segment.StartOffset < 0 || segment.EndOffset <= segment.StartOffset ||
		segment.ArchiveMonth != segment.AcceptedAt.UTC().Format("200601") || !segment.NeedsProjection ||
		segment.SourceBackedRaw || segment.RawIsStandardEvents || len(segment.Raw) != 0 || segment.RawSHA256 != "" ||
		len(segment.Events) == 0 || len(segment.Events) > streamlog.MaxPassiveSegmentEvents {
		return fmt.Errorf("passive journal interval proof is incomplete: %w", streamlog.ErrUnconfirmed)
	}
	for ordinal, event := range segment.Events {
		offset, offsetOK := passiveJournalInt64(event.RawRef["source_offset"])
		index, indexOK := passiveJournalInt64(event.RawRef["source_record_ordinal"])
		producerID, _ := event.RawRef["producer_event_id"].(string)
		if event.EventID != fmt.Sprintf("stream3-%s-%d", id, ordinal) || event.Source != "passive" ||
			event.Type != "discovery" || event.RawRef["backend"] != "passive-discovery" || producerID == "" ||
			!offsetOK || offset != segment.StartOffset || !indexOK || index != int64(ordinal) ||
			event.RawRef["raw_packet_available"] != false {
			return fmt.Errorf("passive journal event proof is incomplete: %w", streamlog.ErrUnconfirmed)
		}
	}
	return nil
}

func passiveJournalInt64(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case float64:
		if number < 0 || number >= 1<<53 || math.Trunc(number) != number {
			return 0, false
		}
		return int64(number), true
	default:
		return 0, false
	}
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

// ReconcileSettledStreamRiskFeatures is an exceptional repair for a stopped
// birth-aware packet source whose independently checkpointed feature lane is
// still attempted. The journal remains attempted; its worker must confirm the
// ClickHouse feature rows and the PostgreSQL risk wake after restart.
func (s *ClickHouseStore) ReconcileSettledStreamRiskFeatures(ctx context.Context, id string, segment streamlog.Segment) error {
	age := time.Since(segment.AcceptedAt)
	if id == "" || id != streamlog.SourceSegmentID(segment) ||
		age < time.Hour || age >= 7*24*time.Hour ||
		segment.Source != "device-signals" || filepath.Base(segment.SourcePath) != "ttl.jsonl" ||
		!segment.RiskFeaturesRequired || !segment.SplitRiskFeatures ||
		!birthAwareStandardEventRaw(segment) {
		return fmt.Errorf("settled packet risk feature proof is incomplete: %w", streamlog.ErrUnconfirmed)
	}
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		return err
	}
	if len(features) == 0 {
		return fmt.Errorf("settled packet segment has no eligible risk features: %w", streamlog.ErrUnconfirmed)
	}
	body, err := s.VerifyStreamBody(ctx, segment)
	if err != nil || !body {
		if err != nil {
			return err
		}
		return fmt.Errorf("settled packet risk feature body is unconfirmed: %w", streamlog.ErrUnconfirmed)
	}
	search, err := s.VerifyStreamSearch(ctx, segment)
	if err != nil || !search {
		if err != nil {
			return err
		}
		return fmt.Errorf("settled packet risk feature search is unconfirmed: %w", streamlog.ErrUnconfirmed)
	}
	missing, err := s.missingStreamRiskFeatures(ctx, segment)
	if err != nil || len(missing) == 0 {
		return err
	}
	if len(missing) != len(features) {
		return fmt.Errorf("partially committed settled packet risk features require manual review: %w", streamlog.ErrUnconfirmed)
	}
	const table = "stream_risk_features_v1"
	if err := s.requireQuietStreamRepair(ctx, []string{table}); err != nil {
		return err
	}
	// Recheck every exact key after the quiet interval; a late original insert
	// leaves this attempt pending instead of authorizing a second token.
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
// the operator command. Consecutive checks include queued async inserts and
// active INSERT requests; no diagnostic query-log retention is needed.
func (s *ClickHouseStore) requireQuietStreamRepair(ctx context.Context, tables []string) error {
	// Other sources can briefly occupy a shared body table after the repaired
	// source has stopped. Give that queue a bounded chance to drain, but never
	// issue a repair insert without two consecutive quiet observations.
	const maxChecks = 4
	quietChecks := 0
	lastBusy := ""
	for check := 0; check < maxChecks; check++ {
		busy := ""
		for _, table := range tables {
			queued, err := s.streamSystemCount(ctx, "SELECT count() FROM system.asynchronous_inserts WHERE database=currentDatabase() AND table="+chQuote(table))
			if err != nil {
				return err
			}
			if queued != 0 {
				busy = fmt.Sprintf("table=%s asynchronous_insert_batches=%d", table, queued)
				break
			}
			active, err := s.streamSystemCount(ctx, "SELECT count() FROM system.processes WHERE current_database=currentDatabase() AND lower(query_kind)='insert' AND positionCaseInsensitive(query,"+chQuote(table)+")>0")
			if err != nil {
				return err
			}
			if active != 0 {
				return fmt.Errorf("ClickHouse repair observed an active insert (table=%s active_inserts=%d): %w", table, active, streamlog.ErrUnconfirmed)
			}
		}
		if busy == "" {
			quietChecks++
			if quietChecks == 2 {
				return nil
			}
		} else {
			quietChecks = 0
			lastBusy = busy
		}
		if check+1 < maxChecks {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(streamRepairQuietInterval):
			}
		}
	}
	return fmt.Errorf("ClickHouse repair did not establish a quiet interval (%s): %w", lastBusy, streamlog.ErrUnconfirmed)
}

func (s *ClickHouseStore) streamSystemCount(ctx context.Context, sql string) (int, error) {
	data, err := s.query(ctx, sql)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
