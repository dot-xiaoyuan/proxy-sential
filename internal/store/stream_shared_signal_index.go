package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// StreamSharedSignalRef is a narrow locator. The event body is read only for
// the affected IP or gateway window, never to find candidate subjects.
type StreamSharedSignalRef struct {
	ObservedAt          time.Time
	IndexedAt           time.Time
	EventKey            string
	Source              string
	Protocol            string
	SensorID            string
	CampusID            string
	AccessDomain        string
	SubjectIP           string
	SubjectMAC          string
	CollectorInstanceID string
	Body                StreamBodyRef
}

// ListStreamSharedSignalRefs bounds one business-key read to the current
// window. IP and MAC are mutually exclusive; an empty indexed subject denotes
// capture-wide coverage for that same registered scope.
func (s *ClickHouseStore) ListStreamSharedSignalRefs(ctx context.Context, scope SharedObservationScope, scopeID, source, epoch, subject string, from, to, after time.Time, afterKey, afterHash string, limit int) ([]StreamSharedSignalRef, error) {
	return s.listStreamSharedSignalRefs(ctx, scope, scopeID, source, epoch, subject, from, to, after, afterKey, afterHash, limit, nil)
}

// A case cites exact source event IDs. Push those keys into ClickHouse before
// reading rows so a busy ten-minute subject window cannot hide its evidence
// behind a page-count limit. An extra bounded page detects excessive physical
// duplicates or conflicts instead of silently accepting a truncated result.
func (s *ClickHouseStore) ListStreamSharedCaseSignalRefs(ctx context.Context, scope SharedObservationScope, scopeID, source, epoch, subject string, from, to time.Time, eventIDs []string) ([]StreamSharedSignalRef, error) {
	if len(eventIDs) == 0 || len(eventIDs) > 100 {
		return nil, errors.New("shared case event key count is out of bounds")
	}
	keys := make([]string, 0, len(eventIDs))
	seen := make(map[string]bool, len(eventIDs))
	for _, id := range eventIDs {
		if id == "" || seen[id] {
			return nil, errors.New("invalid or repeated shared case event id")
		}
		seen[id] = true
		keys = append(keys, epoch+":"+id)
	}
	rows, err := s.listStreamSharedSignalRefs(ctx, scope, scopeID, source, epoch, subject, from, to, time.Time{}, "", "", 201, keys)
	if err != nil || len(rows) < 201 {
		return rows, err
	}
	return nil, errors.New("shared case exact lookup has excessive duplicate rows")
}

func (s *ClickHouseStore) listStreamSharedSignalRefs(ctx context.Context, scope SharedObservationScope, scopeID, source, epoch, subject string, from, to, after time.Time, afterKey, afterHash string, limit int, exactKeys []string) ([]StreamSharedSignalRef, error) {
	if s == nil || scope.SensorID == "" || scope.CampusID == "" || scope.AccessDomain == "" || subject == "" ||
		(source != "handshake-sidecar" && source != "packet-sidecar") || scopeID == "" || epoch == "" || from.IsZero() || !to.After(from) || to.Sub(from) > 12*time.Minute || limit < 1 ||
		(len(exactKeys) == 0 && limit > 100) || (len(exactKeys) != 0 && limit != 201) || (after.IsZero() && afterKey != "") {
		return nil, errors.New("invalid bounded shared signal lookup")
	}
	if (afterKey == "") != (afterHash == "") || (afterHash != "" && len(afterHash) != 64) {
		return nil, errors.New("invalid shared signal cursor")
	}
	field := "subject_ip"
	if source == "packet-sidecar" {
		field = "subject_mac"
	}
	where := "scope_id=" + chQuote(scopeID) + " AND sensor_id=" + chQuote(scope.SensorID) + " AND campus_id=" + chQuote(scope.CampusID) +
		" AND access_domain=" + chQuote(scope.AccessDomain) + " AND source=" + chQuote(source) +
		" AND startsWith(event_key," + chQuote(epoch+":") + ")" +
		" AND " + field + " IN (''," + chQuote(subject) + ")" +
		" AND observed_at>=parseDateTime64BestEffort(" + chQuote(from.UTC().Format(time.RFC3339Nano)) + ",6)" +
		" AND observed_at<=parseDateTime64BestEffort(" + chQuote(to.UTC().Format(time.RFC3339Nano)) + ",6)"
	if source == "handshake-sidecar" {
		where += " AND protocol IN ('handshake','capture_coverage')"
	} else {
		where += " AND protocol IN ('ieee1905_client_association','ieee1905_client_snapshot','capture_coverage')"
	}
	if len(exactKeys) != 0 {
		quoted := make([]string, 0, len(exactKeys))
		for _, key := range exactKeys {
			quoted = append(quoted, chQuote(key))
		}
		where += " AND event_key IN (" + strings.Join(quoted, ",") + ")"
	}
	if !after.IsZero() {
		stamp := "parseDateTime64BestEffort(" + chQuote(after.UTC().Format(time.RFC3339Nano)) + ",6)"
		where += " AND (observed_at>" + stamp + " OR (observed_at=" + stamp + " AND (event_key>" + chQuote(afterKey) + " OR (event_key=" + chQuote(afterKey) + " AND content_sha256>" + chQuote(afterHash) + "))))"
	}
	query := fmt.Sprintf(`SELECT observed_at,indexed_at,event_key,source,protocol,sensor_id,campus_id,access_domain,subject_ip,subject_mac,collector_instance_id,scope_id,content_sha256,archive_month,retention_class,body_ref
FROM stream_event_search PREWHERE %s ORDER BY observed_at,event_key,content_sha256 LIMIT %d
SETTINGS max_threads=1,max_memory_usage=134217728,max_execution_time=5 FORMAT JSONEachRow`, where, limit)
	data, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	result := make([]StreamSharedSignalRef, 0, limit)
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			ObservedAt          string `json:"observed_at"`
			IndexedAt           string `json:"indexed_at"`
			EventKey            string `json:"event_key"`
			Source              string `json:"source"`
			Protocol            string `json:"protocol"`
			SensorID            string `json:"sensor_id"`
			CampusID            string `json:"campus_id"`
			AccessDomain        string `json:"access_domain"`
			SubjectIP           string `json:"subject_ip"`
			SubjectMAC          string `json:"subject_mac"`
			CollectorInstanceID string `json:"collector_instance_id"`
			Scope               string `json:"scope_id"`
			Hash                string `json:"content_sha256"`
			Month               uint32 `json:"archive_month"`
			Class               string `json:"retention_class"`
			BodyRef             string `json:"body_ref"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, err
		}
		observed, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.ObservedAt))
		if err != nil {
			return nil, err
		}
		indexed, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.IndexedAt))
		if err != nil {
			return nil, err
		}
		ref, err := ParseStreamBodyRef(row.BodyRef)
		if err != nil {
			return nil, err
		}
		if row.SensorID != scope.SensorID || row.CampusID != scope.CampusID || row.AccessDomain != scope.AccessDomain || row.Source != source ||
			!strings.HasPrefix(row.EventKey, epoch+":") || row.CollectorInstanceID == "" ||
			(source == "handshake-sidecar" && row.Protocol != "handshake" && row.Protocol != "capture_coverage") ||
			(source == "packet-sidecar" && row.Protocol != "ieee1905_client_association" && row.Protocol != "ieee1905_client_snapshot" && row.Protocol != "capture_coverage") ||
			ref.Key != row.EventKey || ref.Scope != row.Scope || ref.Scope != scopeID || ref.SHA256 != row.Hash || ref.Month != fmt.Sprint(row.Month) || ref.Class != row.Class ||
			observed.Before(from) || observed.After(to) || len(result) >= limit ||
			(source == "handshake-sidecar" && row.SubjectIP != "" && row.SubjectIP != subject) ||
			(source == "packet-sidecar" && row.SubjectMAC != "" && row.SubjectMAC != subject) ||
			(!after.IsZero() && (observed.Before(after) || (observed.Equal(after) && (row.EventKey < afterKey || row.EventKey == afterKey && row.Hash <= afterHash)))) {
			return nil, streamlog.ErrContentConflict
		}
		if len(result) > 0 {
			prior := result[len(result)-1]
			if observed.Before(prior.ObservedAt) || (observed.Equal(prior.ObservedAt) && (row.EventKey < prior.EventKey || row.EventKey == prior.EventKey && row.Hash < prior.Body.SHA256)) {
				return nil, streamlog.ErrContentConflict
			}
		}
		result = append(result, StreamSharedSignalRef{ObservedAt: observed.UTC(), IndexedAt: indexed.UTC(), EventKey: row.EventKey, Source: row.Source, Protocol: row.Protocol, SensorID: row.SensorID, CampusID: row.CampusID, AccessDomain: row.AccessDomain, SubjectIP: row.SubjectIP, SubjectMAC: row.SubjectMAC, CollectorInstanceID: row.CollectorInstanceID, Body: ref})
	}
	return result, nil
}
