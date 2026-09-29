package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

type domainReadSnapshot struct {
	version string
	enabled bool
	now     time.Time
}
type domainReadKey struct{}

func (s *PostgresStore) domainSnapshot(ctx context.Context) (context.Context, error) {
	if _, ok := ctx.Value(domainReadKey{}).(domainReadSnapshot); ok {
		return ctx, nil
	}
	version, enabled, err := s.activeDomainVersion(ctx)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, domainReadKey{}, domainReadSnapshot{version, enabled, time.Now().UTC()}), nil
}
func (s *PostgresStore) activeDomainVersion(ctx context.Context) (string, bool, error) {
	if snapshot, ok := ctx.Value(domainReadKey{}).(domainReadSnapshot); ok {
		return snapshot.version, snapshot.enabled, nil
	}
	var version string
	var enabled bool
	err := s.db.QueryRowContext(ctx, `SELECT active_version,enabled FROM domain_recognition_state WHERE singleton`).Scan(&version, &enabled)
	if err == sql.ErrNoRows {
		return fingerprint.Default().Version(), os.Getenv("PROXY_SENTINEL_BRAND_INFERENCE_ENABLED") != "false", nil
	}
	return version, enabled && os.Getenv("PROXY_SENTINEL_BRAND_INFERENCE_ENABLED") != "false", err
}

// The event ledger, not lifetime counters or the UI's evidence limit, defines
// the window. Event IDs are unique per version, including replay retries.
func (s *PostgresStore) windowDomainEvidence(ctx context.Context, endpointID, version string, now time.Time) ([]fingerprint.DomainEvidence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rule_match,observation->>'event_source',min(observation->>'attribution_method'),min(observed_at),max(observed_at),count(*),to_json((array_agg(event_id ORDER BY observed_at,event_id))[1:10])
 FROM endpoint_domain_evidence_events WHERE endpoint_id=$1 AND rule_version=$2 AND observed_at >= $3 AND observed_at <= $4 AND rule_match IS NOT NULL
 GROUP BY rule_match,observation->>'event_source' ORDER BY min(observed_at),rule_match::text,observation->>'event_source'`, endpointID, version, now.Add(-fingerprint.BrandEvidenceWindow), now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fingerprint.DomainEvidence{}
	for rows.Next() {
		var v fingerprint.DomainEvidence
		var match, ids []byte
		var first, last time.Time
		if err := rows.Scan(&match, &v.EventSource, &v.AttributionMethod, &first, &last, &v.Count, &ids); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(match, &v.Match); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(ids, &v.EventIDs); err != nil {
			return nil, err
		}
		v.RuleVersion = version
		v.FirstSeen = first.UTC().Format(time.RFC3339Nano)
		v.LastSeen = last.UTC().Format(time.RFC3339Nano)
		out = append(out, v)
	}
	return out, rows.Err()
}

func applyDomainRecognition(item *EndpointDeviceInventory, evidence []fingerprint.DomainEvidence, version string, now time.Time, enabled bool) {
	ecosystem := fingerprint.EvaluateEcosystem(evidence)
	item.EcosystemConfidence = ecosystem.Confidence
	item.EcosystemConflict = ecosystem.Conflict
	item.EcosystemEvidenceCount = ecosystem.EvidenceCount
	if ecosystem.Displayable && !ecosystem.Conflict {
		item.EcosystemHint = ecosystem.Hint
	}
	// item always starts with independent device fields; never read back fused
	// confidence from a stored domain profile as input to this calculation.
	if !item.RecognitionConflict {
		if brand, score, ok := fingerprint.FuseEcosystemBrand(item.Brand, item.BrandConfidence, item.RecognitionSource, ecosystem); ok {
			item.Brand = brand
			item.BrandConfidence = score
			item.RecognitionEvidence = append(item.RecognitionEvidence, "品牌生态线索与独立设备信号一致")
		}
	}
	if enabled {
		knownScore := item.BrandConfidence
		if item.RecognitionConflict {
			knownScore = 0
		}
		inference := fingerprint.InferBrand(evidence, version, now, item.Brand, knownScore)
		item.BrandInference = &inference
	}
}

func (s *PostgresStore) enrichDomainRecognition(ctx context.Context, item *EndpointDeviceInventory) error {
	version, enabled, err := s.activeDomainVersion(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if snapshot, ok := ctx.Value(domainReadKey{}).(domainReadSnapshot); ok {
		now = snapshot.now
	}
	evidence, err := s.windowDomainEvidence(ctx, item.EndpointID, version, now)
	if err != nil {
		return err
	}
	applyDomainRecognition(item, evidence, version, now, enabled)
	return nil
}

func (s *PostgresStore) refreshBrandInference(ctx context.Context, endpointID, version string) error {
	now := time.Now().UTC()
	evidence, err := s.windowDomainEvidence(ctx, endpointID, version, now)
	if err != nil {
		return err
	}
	endpoint, ok, err := s.getEndpointEntity(ctx, endpointID)
	if err != nil || !ok {
		return err
	}
	item := BuildEndpointDeviceInventory(EndpointIdentityProfile{EndpointID: endpointID, Endpoint: endpoint})
	applyDomainRecognition(&item, evidence, version, now, true)
	result, err := json.Marshal(item.BrandInference)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_brand_inferences(endpoint_id,rule_version,result) VALUES($1,$2,$3) ON CONFLICT(endpoint_id,rule_version) DO UPDATE SET result=EXCLUDED.result,updated_at=now()`, endpointID, version, result)
	return err
}

type DomainRecognitionStatus struct {
	ActiveVersion  string `json:"active_domain_version"`
	PendingVersion string `json:"pending_domain_version"`
	LastError      string `json:"domain_processing_error"`
}
type DomainRecognitionStatusReader interface {
	DomainRecognitionStatus(context.Context) (DomainRecognitionStatus, error)
}

func (s *DBStore) DomainRecognitionStatus(ctx context.Context) (DomainRecognitionStatus, error) {
	var out DomainRecognitionStatus
	err := s.pg.db.QueryRowContext(ctx, `SELECT active_version,pending_version,last_error FROM domain_recognition_state WHERE singleton`).Scan(&out.ActiveVersion, &out.PendingVersion, &out.LastError)
	if err == sql.ErrNoRows {
		out.ActiveVersion = fingerprint.Default().Version()
		return out, nil
	}
	return out, err
}
