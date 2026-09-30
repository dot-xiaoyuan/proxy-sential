package store

import (
	"context"
	"database/sql"
	"time"
)

type SharedRiskAudit struct {
	GenerationID          string    `json:"generation_id,omitempty"`
	AsOf                  time.Time `json:"as_of,omitempty"`
	CoverageState         string    `json:"coverage_state"`
	Stale                 bool      `json:"stale"`
	CurrentInvestigations int       `json:"current_investigations"`
	CurrentConfirmed      int       `json:"current_confirmed"`
	RiskSnapshots         int       `json:"risk_snapshots"`
	OpenCases             int       `json:"open_cases"`
	InvalidConfirmed      int       `json:"invalid_confirmed"`
	NonSharedRisks        int       `json:"non_shared_risks"`
	NonSharedOpenCases    int       `json:"non_shared_open_cases"`
	VPNRiskLinks          int       `json:"vpn_risk_links"`
	Consistent            bool      `json:"consistent"`
}

func (s *PostgresStore) AuditSharedRiskState(ctx context.Context) (SharedRiskAudit, error) {
	result := SharedRiskAudit{CoverageState: "unknown", Stale: true}
	var asOf sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT
 COALESCE((SELECT generation_id FROM shared_behavior_generations ORDER BY window_end DESC,created_at DESC LIMIT 1),''),
 (SELECT window_end FROM shared_behavior_generations ORDER BY window_end DESC,created_at DESC LIMIT 1),
 COALESCE((SELECT coverage_state FROM shared_behavior_generations ORDER BY window_end DESC,created_at DESC LIMIT 1),'unknown'),
 (SELECT count(*) FROM shared_behavior_observations WHERE current),
 (SELECT count(DISTINCT host(ip)) FROM shared_behavior_observations WHERE current AND status='confirmed' AND coverage_state='verified'),
 (SELECT count(*) FROM risk_snapshots),
 (SELECT count(*) FROM risk_cases WHERE ruleset_version LIKE 'shared-behavior/%' AND status NOT IN ('resolved','closed')),
 (SELECT count(*) FROM shared_behavior_observations WHERE current AND status='confirmed' AND (
   coverage_state<>'verified' OR COALESCE(observation->>'strong_anchor','') NOT IN ('ieee1905_association','coexisting_device_identities')
   OR COALESCE(NULLIF(observation->>'device_lower_bound','')::integer,0)<2)),
 (SELECT count(*) FROM risk_snapshots WHERE COALESCE(metadata->>'risk_kind','')<>'shared_access'),
 (SELECT count(*) FROM risk_cases WHERE status NOT IN ('resolved','closed') AND COALESCE(ruleset_version,'') NOT LIKE 'shared-behavior/%'),
 (SELECT count(*) FROM risk_snapshots r WHERE EXISTS(
   SELECT 1 FROM jsonb_array_elements_text(r.evidence_ids) linked(id)
   JOIN evidence e ON e.evidence_id=linked.id
   WHERE e.type LIKE 'vpn_proxy_%' OR e.type IN ('encrypted_tunnel_behavior','ai_relay_domain_usage')))`).
		Scan(&result.GenerationID, &asOf, &result.CoverageState, &result.CurrentInvestigations, &result.CurrentConfirmed,
			&result.RiskSnapshots, &result.OpenCases, &result.InvalidConfirmed, &result.NonSharedRisks, &result.NonSharedOpenCases, &result.VPNRiskLinks)
	if err != nil {
		return result, err
	}
	if asOf.Valid {
		result.AsOf = asOf.Time.UTC()
	}
	result.Stale = result.CoverageState != "verified" || !asOf.Valid || time.Since(result.AsOf) > 20*time.Minute
	result.Consistent = !result.Stale && result.InvalidConfirmed == 0 && result.NonSharedRisks == 0 && result.NonSharedOpenCases == 0 && result.VPNRiskLinks == 0 && result.CurrentConfirmed == result.RiskSnapshots && result.RiskSnapshots == result.OpenCases
	return result, nil
}
