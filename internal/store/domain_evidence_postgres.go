package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

type EndpointDomainEvidence struct {
	RuleDomain        string   `json:"rule_domain,omitempty"`
	SourceURL         string   `json:"source_url,omitempty"`
	SourceVersion     string   `json:"source_version,omitempty"`
	Service           string   `json:"service,omitempty"`
	Purpose           string   `json:"purpose,omitempty"`
	BrandEligible     bool     `json:"brand_eligible,omitempty"`
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
	if _, err := s.db.ExecContext(ctx, `INSERT INTO domain_rule_versions(version,rules) VALUES($1,$2) ON CONFLICT DO NOTHING`, library.Version(), library.DomainRulesJSON()); err != nil {
		return result, err
	}
	touched := map[string]struct{}{}
	validEndpoints := map[string]bool{}
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
		valid, checked := validEndpoints[attributed.EndpointID]
		if !checked {
			if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_entities WHERE endpoint_id=$1 AND entity_role='endpoint')`, attributed.EndpointID).Scan(&valid); err != nil {
				return result, err
			}
			validEndpoints[attributed.EndpointID] = valid
		}
		if !valid {
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
		if err := s.refreshBrandInference(ctx, endpointID, library.Version()); err != nil {
			return result, err
		}
	}
	return result, nil
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
	observationJSON, _ := json.Marshal(observation)
	matchJSON, _ := json.Marshal(match)
	result, err := tx.ExecContext(ctx, `INSERT INTO endpoint_domain_evidence_events(rule_version,event_id,ecosystem,endpoint_id,observed_at,observation,rule_match) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, version, observation.EventID, match.Ecosystem, observation.EndpointID, when, observationJSON, matchJSON)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE endpoint_domain_evidence_events SET observation=$4,rule_match=$5 WHERE rule_version=$1 AND event_id=$2 AND ecosystem=$3 AND rule_match IS NULL`, version, observation.EventID, match.Ecosystem, observationJSON, matchJSON); err != nil {
			return err
		}
		return tx.Commit()
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

func (s *PostgresStore) ListEndpointDomainEvidence(ctx context.Context, endpointID string, limit int) ([]EndpointDomainEvidence, error) {
	version, _, err := s.activeDomainVersion(ctx)
	if err != nil {
		return nil, err
	}
	evidence, err := s.windowDomainEvidence(ctx, endpointID, version, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].LastSeen > evidence[j].LastSeen })
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	if len(evidence) > limit {
		evidence = evidence[:limit]
	}
	out := []EndpointDomainEvidence{}
	for _, v := range evidence {
		out = append(out, EndpointDomainEvidence{EndpointID: endpointID, Domain: v.Match.Domain, Ecosystem: v.Match.Ecosystem, EventSource: v.EventSource, AttributionMethod: v.AttributionMethod, RuleSource: v.Match.Source, RuleVersion: version, Category: v.Match.Category, Confidence: v.Match.Confidence, FirstSeen: v.FirstSeen, LastSeen: v.LastSeen, Count: v.Count, EventIDs: v.EventIDs, RuleDomain: v.Match.RuleDomain, SourceURL: v.Match.SourceURL, SourceVersion: v.Match.SourceVersion, Service: v.Match.Service, Purpose: v.Match.Purpose, BrandEligible: v.Match.BrandEligible})
	}
	return out, nil
}
