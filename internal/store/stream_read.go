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
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

// StreamBodyRef is the complete physical locator of one authoritative event
// body. Callers must retain all fields instead of querying every month by ID.
type StreamBodyRef struct {
	Epoch  string `json:"epoch,omitempty"`
	Class  string `json:"class"`
	Month  string `json:"month"`
	Scope  string `json:"scope"`
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

type StreamEvidence struct {
	Event        normalized.Event
	Body         json.RawMessage
	RawSource    []byte
	RawAvailable bool
	BodySHA256   string
	RawSHA256    string
	rawSegmentID string
}

func (ref StreamBodyRef) Validate() error {
	if ref.Class != "short" && ref.Class != "evidence" {
		return errors.New("invalid stream body retention class")
	}
	if len(ref.Month) != 6 {
		return errors.New("invalid stream body archive month")
	}
	if _, err := time.Parse("200601", ref.Month); err != nil {
		return fmt.Errorf("invalid stream body archive month: %w", err)
	}
	if ref.Scope == "" || ref.Key == "" {
		return errors.New("stream body scope and event key are required")
	}
	if len(ref.SHA256) != 64 {
		return errors.New("invalid stream body hash")
	}
	if _, err := hex.DecodeString(ref.SHA256); err != nil {
		return fmt.Errorf("invalid stream body hash: %w", err)
	}
	return nil
}

func ParseStreamBodyRef(raw string) (StreamBodyRef, error) {
	var ref StreamBodyRef
	if err := json.Unmarshal([]byte(raw), &ref); err != nil {
		return StreamBodyRef{}, err
	}
	if err := ref.Validate(); err != nil {
		return StreamBodyRef{}, err
	}
	return ref, nil
}

// GetStreamEventByRef reads only one retained class, month and scoped key. It
// verifies both the row hash and body bytes before returning evidence.
func (s *ClickHouseStore) GetStreamEventByRef(ctx context.Context, ref StreamBodyRef) (normalized.Event, bool, error) {
	evidence, found, err := s.getStreamBody(ctx, ref)
	return evidence.Event, found, err
}

// GetStreamEventsByRefs resolves a bounded set of narrow index rows in one
// primary-key lookup per retention class and archive month. It verifies the
// stored hash and the body bytes; a missing or conflicting row cannot be
// interpreted as an empty event.
func (s *ClickHouseStore) GetStreamEventsByRefs(ctx context.Context, refs []StreamBodyRef) (map[StreamBodyRef]normalized.Event, error) {
	bodies, err := s.getStreamBodiesByRefs(ctx, refs)
	if err != nil {
		return nil, err
	}
	result := make(map[StreamBodyRef]normalized.Event, len(bodies))
	for ref, item := range bodies {
		result[ref] = item.Event
	}
	return result, nil
}

// getStreamBodiesByRefs returns the exact archived bytes as well as the
// decoded event. Case creation can protect up to 100 originals without
// issuing one ClickHouse query per reference inside its PostgreSQL transaction.
func (s *ClickHouseStore) getStreamBodiesByRefs(ctx context.Context, refs []StreamBodyRef) (map[StreamBodyRef]StreamEvidence, error) {
	if s == nil || len(refs) == 0 || len(refs) > 100 {
		return nil, errors.New("stream batch body read needs one to 100 references")
	}
	type groupKey struct{ class, month string }
	groups := make(map[groupKey]map[string]StreamBodyRef)
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return nil, err
		}
		group := groupKey{ref.Class, ref.Month}
		if groups[group] == nil {
			groups[group] = make(map[string]StreamBodyRef)
		}
		key := ref.Scope + "\x00" + ref.Key
		if prior, found := groups[group][key]; found && prior.SHA256 != ref.SHA256 {
			return nil, streamlog.ErrContentConflict
		}
		groups[group][key] = ref
	}
	order := make([]groupKey, 0, len(groups))
	for key := range groups {
		order = append(order, key)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].month != order[j].month {
			return order[i].month < order[j].month
		}
		return order[i].class < order[j].class
	})
	result := make(map[StreamBodyRef]StreamEvidence, len(refs))
	for _, group := range order {
		expected := groups[group]
		keys := make([]string, 0, len(expected))
		for _, ref := range expected {
			keys = append(keys, "("+chQuote(ref.Scope)+","+chQuote(ref.Key)+")")
		}
		sort.Strings(keys)
		limit := 101 * len(expected)
		query := "SELECT scope_id,event_key,content_sha256,body FROM stream_event_body_" + group.class +
			" WHERE archive_month=" + group.month + " AND (scope_id,event_key) IN (" + strings.Join(keys, ",") + ")" +
			fmt.Sprintf(" LIMIT %d SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=10 FORMAT JSONEachRow", limit)
		data, err := s.query(ctx, query)
		if err != nil {
			return nil, err
		}
		seen := make(map[string]int, len(expected))
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var row struct {
				Scope string `json:"scope_id"`
				Key   string `json:"event_key"`
				Hash  string `json:"content_sha256"`
				Body  string `json:"body"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				return nil, err
			}
			key := row.Scope + "\x00" + row.Key
			ref, found := expected[key]
			if !found || row.Hash != ref.SHA256 || seen[key] >= 100 {
				return nil, streamlog.ErrContentConflict
			}
			sum := sha256.Sum256([]byte(row.Body))
			if hex.EncodeToString(sum[:]) != ref.SHA256 {
				return nil, streamlog.ErrContentConflict
			}
			var event normalized.Event
			if err := json.Unmarshal([]byte(row.Body), &event); err != nil {
				return nil, err
			}
			if event.EventID == "" || (seen[key] > 0 && result[ref].Event.EventID != event.EventID) {
				return nil, streamlog.ErrContentConflict
			}
			result[ref] = StreamEvidence{Event: event, Body: json.RawMessage(row.Body), BodySHA256: ref.SHA256}
			seen[key]++
		}
		if len(seen) != len(expected) {
			return nil, streamlog.ErrUnconfirmed
		}
	}
	return result, nil
}

func (s *ClickHouseStore) GetStreamEvidenceByRef(ctx context.Context, ref StreamBodyRef) (StreamEvidence, bool, error) {
	evidence, found, err := s.getStreamBody(ctx, ref)
	if err != nil || !found || evidence.rawSegmentID == "" {
		return evidence, found, err
	}
	query := "SELECT raw_sha256,raw_base64 FROM stream_source_raw WHERE archive_month=" + ref.Month +
		" AND segment_id=" + chQuote(evidence.rawSegmentID) +
		" SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=10 FORMAT JSONEachRow"
	data, err := s.query(ctx, query)
	if err != nil {
		return StreamEvidence{}, false, err
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Hash string `json:"raw_sha256"`
			Raw  string `json:"raw_base64"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return StreamEvidence{}, false, err
		}
		raw, err := base64.StdEncoding.DecodeString(row.Raw)
		if err != nil {
			return StreamEvidence{}, false, err
		}
		sum := sha256.Sum256(raw)
		if row.Hash != evidence.RawSHA256 || hex.EncodeToString(sum[:]) != evidence.RawSHA256 || (evidence.RawAvailable && !bytes.Equal(evidence.RawSource, raw)) {
			return StreamEvidence{}, false, streamlog.ErrContentConflict
		}
		evidence.RawSource, evidence.RawAvailable = raw, true
	}
	if !evidence.RawAvailable {
		return StreamEvidence{}, false, streamlog.ErrUnconfirmed
	}
	return evidence, true, nil
}

func (s *ClickHouseStore) getStreamBody(ctx context.Context, ref StreamBodyRef) (StreamEvidence, bool, error) {
	if err := ref.Validate(); err != nil {
		return StreamEvidence{}, false, err
	}
	query := "SELECT content_sha256,body,raw_segment_id,raw_sha256 FROM stream_event_body_" + ref.Class +
		" WHERE archive_month=" + ref.Month + " AND scope_id=" + chQuote(ref.Scope) +
		" AND event_key=" + chQuote(ref.Key) +
		" LIMIT 101 SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=10 FORMAT JSONEachRow"
	data, err := s.query(ctx, query)
	if err != nil {
		return StreamEvidence{}, false, err
	}
	var result StreamEvidence
	found := false
	rows := 0
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		rows++
		if rows > 100 {
			return StreamEvidence{}, false, streamlog.ErrContentConflict
		}
		var row struct {
			Hash         string `json:"content_sha256"`
			Body         string `json:"body"`
			RawSegmentID string `json:"raw_segment_id"`
			RawSHA256    string `json:"raw_sha256"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return StreamEvidence{}, false, err
		}
		sum := sha256.Sum256([]byte(row.Body))
		if row.Hash != ref.SHA256 || hex.EncodeToString(sum[:]) != ref.SHA256 {
			return StreamEvidence{}, false, streamlog.ErrContentConflict
		}
		var event normalized.Event
		if err := json.Unmarshal([]byte(row.Body), &event); err != nil {
			return StreamEvidence{}, false, err
		}
		if found && (result.Event.EventID != event.EventID || result.rawSegmentID != row.RawSegmentID || result.RawSHA256 != row.RawSHA256) {
			return StreamEvidence{}, false, streamlog.ErrContentConflict
		}
		result = StreamEvidence{Event: event, Body: json.RawMessage(row.Body), BodySHA256: ref.SHA256, RawSHA256: row.RawSHA256, rawSegmentID: row.RawSegmentID}
		found = true
	}
	return result, found, nil
}
