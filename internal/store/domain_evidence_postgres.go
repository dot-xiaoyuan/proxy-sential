package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

type EndpointDomainEvidence struct {
	EndpointID        string   `json:"endpoint_id"`
	IP                string   `json:"ip,omitempty"`
	AuthSessionID     string   `json:"auth_session_id,omitempty"`
	Domain            string   `json:"domain"`
	Ecosystem         string   `json:"ecosystem"`
	EventSource       string   `json:"event_source"`
	AttributionMethod string   `json:"attribution_method"`
	RuleSource        string   `json:"rule_source"`
	RuleVersion       string   `json:"rule_version"`
	Category          string   `json:"category"`
	Confidence        float64  `json:"confidence"`
	FirstSeen         string   `json:"first_seen"`
	LastSeen          string   `json:"last_seen"`
	Count             int      `json:"count"`
	EventIDs          []string `json:"event_ids_sample,omitempty"`
}

type DomainBackfillProgress struct {
	Version         string                       `json:"version"`
	Status          string                       `json:"status"`
	CursorTimestamp string                       `json:"cursor_timestamp,omitempty"`
	CursorEventID   string                       `json:"cursor_event_id,omitempty"`
	Processed       int                          `json:"processed"`
	Attributed      int                          `json:"attributed"`
	Matched         int                          `json:"matched"`
	LastError       string                       `json:"last_error,omitempty"`
	Observations    []DomainEcosystemObservation `json:"-"`
}

type DomainEcosystemObservation struct {
	DomainObservation
	Ecosystem   string  `json:"ecosystem"`
	Category    string  `json:"category"`
	RuleSource  string  `json:"rule_source"`
	RuleVersion string  `json:"rule_version"`
	Confidence  float64 `json:"confidence"`
	Attributed  bool    `json:"attributed"`
}

func (s *PostgresStore) ProcessDomainEvents(ctx context.Context, events []normalized.Event, library *fingerprint.Library) (DomainBackfillProgress, error) {
	result := DomainBackfillProgress{Version: library.Version()}
	touched := map[string]struct{}{}
	for _, event := range events {
		observation, observable := ExtractDomainObservation(event)
		if !observable {
			continue
		}
		result.Processed++
		match, matched := library.MatchDomain(observation.Domain)
		if !matched {
			continue
		}
		result.Matched++
		matchedObservation := DomainEcosystemObservation{DomainObservation: observation, Ecosystem: match.Ecosystem, Category: match.Category, RuleSource: match.Source, RuleVersion: library.Version(), Confidence: match.Confidence}
		attributed, found, err := AttributeDomainObservation(ctx, observation, s)
		if err != nil {
			return result, err
		}
		if !found {
			result.Observations = append(result.Observations, matchedObservation)
			continue
		}
		result.Attributed++
		matchedObservation.DomainObservation = attributed
		matchedObservation.Attributed = true
		result.Observations = append(result.Observations, matchedObservation)
		if err := s.persistDomainEvidence(ctx, attributed, match, library.Version()); err != nil {
			return result, err
		}
		touched[attributed.EndpointID] = struct{}{}
	}
	for endpointID := range touched {
		if err := s.updateEndpointEcosystemProfile(ctx, endpointID); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s *PostgresStore) updateEndpointEcosystemProfile(ctx context.Context, endpointID string) error {
	ecosystem, _, err := s.endpointEcosystem(ctx, endpointID)
	if err != nil {
		return err
	}
	var brand, source string
	var brandConfidence float64
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(brand,''),brand_confidence,COALESCE(recognition_source,'') FROM endpoint_device_profiles WHERE endpoint_id=$1`, endpointID).Scan(&brand, &brandConfidence, &source)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	brand, brandConfidence, _ = fingerprint.FuseEcosystemBrand(brand, brandConfidence, source, ecosystem)
	hint := ""
	if ecosystem.Displayable && !ecosystem.Conflict {
		hint = ecosystem.Hint
	}
	_, err = s.db.ExecContext(ctx, `UPDATE endpoint_device_profiles SET brand=NULLIF($2,''),brand_confidence=$3,ecosystem_hint=NULLIF($4,''),ecosystem_confidence=$5,ecosystem_conflict=$6,ecosystem_evidence_count=$7,updated_at=now() WHERE endpoint_id=$1`, endpointID, brand, brandConfidence, hint, ecosystem.Confidence, ecosystem.Conflict, ecosystem.EvidenceCount)
	return err
}

func (s *PostgresStore) persistDomainEvidence(ctx context.Context, observation DomainObservation, match fingerprint.DomainMatch, version string) error {
	when, err := time.Parse(time.RFC3339Nano, observation.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid domain observation timestamp: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var endpointExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_entities WHERE endpoint_id=$1)`, observation.EndpointID).Scan(&endpointExists); err != nil {
		return err
	}
	if !endpointExists {
		return nil
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO endpoint_domain_evidence_events(rule_version,event_id,ecosystem,endpoint_id,observed_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, version, observation.EventID, match.Ecosystem, observation.EndpointID, when)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 0 {
		return err
	}
	sample, _ := json.Marshal([]string{observation.EventID})
	_, err = tx.ExecContext(ctx, `
INSERT INTO endpoint_domain_evidence(endpoint_id,domain,ecosystem,event_source,attribution_method,auth_session_id,rule_source,rule_version,category,confidence,first_seen,last_seen,hit_count,event_ids_sample)
VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$11,1,$12)
ON CONFLICT(endpoint_id,domain,ecosystem,event_source,rule_version) DO UPDATE SET
  first_seen=LEAST(endpoint_domain_evidence.first_seen,EXCLUDED.first_seen),
  last_seen=GREATEST(endpoint_domain_evidence.last_seen,EXCLUDED.last_seen),
  hit_count=endpoint_domain_evidence.hit_count+1,
  auth_session_id=COALESCE(EXCLUDED.auth_session_id,endpoint_domain_evidence.auth_session_id),
  attribution_method=EXCLUDED.attribution_method,
  event_ids_sample=(SELECT COALESCE(jsonb_agg(value),'[]'::jsonb) FROM (SELECT DISTINCT value FROM jsonb_array_elements_text(endpoint_domain_evidence.event_ids_sample || EXCLUDED.event_ids_sample) value LIMIT 10) samples),
  updated_at=now()`, observation.EndpointID, observation.Domain, match.Ecosystem, observation.EventSource, observation.AttributionMethod, observation.AuthSessionID, match.Source, version, match.Category, match.Confidence, when, sample)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) ListEndpointDomainEvidence(ctx context.Context, endpointID string, limit int) ([]EndpointDomainEvidence, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id,domain,ecosystem,event_source,attribution_method,COALESCE(auth_session_id,''),rule_source,rule_version,category,confidence,first_seen,last_seen,hit_count,event_ids_sample FROM endpoint_domain_evidence WHERE endpoint_id=$1 ORDER BY last_seen DESC,domain LIMIT $2`, endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []EndpointDomainEvidence{}
	for rows.Next() {
		var item EndpointDomainEvidence
		var first, last time.Time
		var sample []byte
		if err := rows.Scan(&item.EndpointID, &item.Domain, &item.Ecosystem, &item.EventSource, &item.AttributionMethod, &item.AuthSessionID, &item.RuleSource, &item.RuleVersion, &item.Category, &item.Confidence, &first, &last, &item.Count, &sample); err != nil {
			return nil, err
		}
		item.FirstSeen = first.UTC().Format(time.RFC3339Nano)
		item.LastSeen = last.UTC().Format(time.RFC3339Nano)
		_ = json.Unmarshal(sample, &item.EventIDs)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) endpointEcosystem(ctx context.Context, endpointID string) (fingerprint.EcosystemResult, []EndpointDomainEvidence, error) {
	items, err := s.ListEndpointDomainEvidence(ctx, endpointID, 200)
	if err != nil {
		return fingerprint.EcosystemResult{}, nil, err
	}
	evidence := make([]fingerprint.DomainEvidence, 0, len(items))
	for _, item := range items {
		evidence = append(evidence, fingerprint.DomainEvidence{Match: fingerprint.DomainMatch{Domain: item.Domain, Ecosystem: item.Ecosystem, Category: item.Category, Confidence: item.Confidence, Source: item.RuleSource}, FirstSeen: item.FirstSeen, LastSeen: item.LastSeen, Count: item.Count})
	}
	return fingerprint.EvaluateEcosystem(evidence), items, nil
}

func scanDomainBackfillProgress(row *sql.Row, version string) (DomainBackfillProgress, error) {
	result := DomainBackfillProgress{Version: version}
	var cursor, lastError sql.NullString
	var cursorTime sql.NullTime
	err := row.Scan(&result.Status, &cursorTime, &cursor, &result.Processed, &result.Attributed, &result.Matched, &lastError)
	if cursorTime.Valid {
		result.CursorTimestamp = cursorTime.Time.UTC().Format(time.RFC3339Nano)
	}
	if cursor.Valid {
		result.CursorEventID = cursor.String
	}
	if lastError.Valid {
		result.LastError = lastError.String
	}
	return result, err
}

func (s *PostgresStore) loadDomainBackfillProgress(ctx context.Context, version string) (DomainBackfillProgress, error) {
	return scanDomainBackfillProgress(s.db.QueryRowContext(ctx, `SELECT status,cursor_timestamp,cursor_event_id,processed,attributed,matched,last_error FROM domain_evidence_backfill_jobs WHERE version=$1`, version), version)
}

func (s *PostgresStore) saveDomainBackfillFailure(version string, err error) {
	if err == nil {
		return
	}
	_, _ = s.db.ExecContext(context.Background(), `UPDATE domain_evidence_backfill_jobs SET status='failed',last_error=$2,updated_at=now() WHERE version=$1`, version, strings.TrimSpace(err.Error()))
}
