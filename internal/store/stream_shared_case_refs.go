package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/streamlog"
)

type sharedCaseEventKey struct {
	Source   string
	Instance string
	EventID  string
}

// ReadStreamSharedCaseRefs resolves the exact records cited by one committed
// decision through the narrow ClickHouse search index. No per-event receipt is
// added to PostgreSQL on the normal ingest path. The caller fetches and hashes
// the original bodies before the case snapshot transaction commits.
func (s *DBStore) ReadStreamSharedCaseRefs(ctx context.Context, observationID, generationID string) ([]StreamBodyRef, error) {
	if s == nil || s.pg == nil || s.ch == nil || observationID == "" || generationID == "" {
		return nil, errors.New("shared case source reader and generation are required")
	}
	var raw []byte
	err := s.pg.db.QueryRowContext(ctx, `SELECT d.document FROM policy_decision_records d
 JOIN shared_behavior_observations o ON o.observation_id=d.observation_id
 WHERE d.observation_id=$1 AND o.generation_id=$2 AND o.current
 ORDER BY d.first_received_at DESC,d.decision_id DESC LIMIT 1`, observationID, generationID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var decision struct {
		Evidence sharedaccess.Window `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &decision); err != nil {
		return nil, err
	}
	w := decision.Evidence
	if w.ID != observationID || w.SensorID == "" || w.CampusID == "" || w.AccessDomain == "" || w.IP == "" ||
		w.From.IsZero() || !w.To.After(w.From) || w.To.Sub(w.From) > 10*time.Minute {
		return nil, streamlog.ErrContentConflict
	}
	wanted := make(map[sharedCaseEventKey]bool)
	add := func(source, instance, eventID string) error {
		epoch, scope := w.SourceEpochs[source], w.SourceScopes[source]
		if epoch == "" && scope == "" {
			return nil // Legacy evidence keeps its own compatibility path.
		}
		if epoch == "" || scope == "" || instance == "" || eventID == "" {
			return streamlog.ErrContentConflict
		}
		wanted[sharedCaseEventKey{source, instance, eventID}] = true
		if len(wanted) > 100 {
			return fmt.Errorf("shared case source evidence exceeds 100 originals")
		}
		return nil
	}
	for _, record := range w.Records {
		if err := add(record.Source, record.InstanceID, record.EventID); err != nil {
			return nil, err
		}
	}
	for _, fact := range w.CoverageFacts {
		if err := add(fact.Source, fact.Instance, fact.EventID); err != nil {
			return nil, err
		}
	}
	if len(wanted) == 0 {
		return nil, fmt.Errorf("shared case has no current source originals: %w", streamlog.ErrUnconfirmed)
	}
	seen := make(map[sharedCaseEventKey]StreamBodyRef, len(wanted))
	scope := SharedObservationScope{SensorID: w.SensorID, CampusID: w.CampusID, AccessDomain: w.AccessDomain, IP: w.IP}
	for _, source := range []string{"handshake-sidecar", "packet-sidecar"} {
		ids := make([]string, 0, len(wanted))
		seenID := make(map[string]bool)
		for key := range wanted {
			if key.Source == source && !seenID[key.EventID] {
				ids = append(ids, key.EventID)
				seenID[key.EventID] = true
			}
		}
		if len(ids) == 0 {
			continue
		}
		sort.Strings(ids)
		subject := w.IP
		if source == "packet-sidecar" {
			subject = w.GatewayMAC
		}
		if subject == "" || w.SourceEpochs[source] == "" || w.SourceScopes[source] == "" {
			return nil, streamlog.ErrContentConflict
		}
		page, err := s.ch.ListStreamSharedCaseSignalRefs(ctx, scope, w.SourceScopes[source], source, w.SourceEpochs[source], subject,
			w.From.Add(-time.Minute), w.To.Add(time.Minute), ids)
		if err != nil {
			return nil, err
		}
		for _, row := range page {
			key := sharedCaseEventKey{row.Source, row.CollectorInstanceID, strings.TrimPrefix(row.EventKey, w.SourceEpochs[source]+":")}
			if !wanted[key] {
				return nil, streamlog.ErrContentConflict
			}
			if row.Body.Class != "evidence" || row.Body.Epoch != w.SourceEpochs[source] || row.Body.Validate() != nil {
				return nil, streamlog.ErrContentConflict
			}
			if prior, exists := seen[key]; exists && prior != row.Body {
				return nil, streamlog.ErrContentConflict
			}
			seen[key] = row.Body
		}
	}
	if len(seen) != len(wanted) {
		return nil, fmt.Errorf("shared case source originals are not all archived: %w", streamlog.ErrUnconfirmed)
	}
	result := make([]StreamBodyRef, 0, len(seen))
	for _, ref := range seen {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		return a.Epoch+a.Scope+a.Key < b.Epoch+b.Scope+b.Key
	})
	return result, nil
}
