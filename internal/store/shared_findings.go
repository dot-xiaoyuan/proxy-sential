package store

import (
	"context"
	"encoding/json"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

// Scalar primary-key lookups run only for the returned page. Links to a
// case appear when its normal synchronization transaction has committed.
const sharedFindingDocument = `observation || coalesce((SELECT jsonb_strip_nulls(jsonb_build_object('case_id',c.case_id,'action_id',a.action_id,
 'account_id',CASE WHEN NOT current AND coalesce(observation->>'account_id','')='' THEN nullif(f.account_id,'') END,
 'review_reason',CASE WHEN NOT current AND coalesce(observation->>'review_reason','')='' THEN nullif(f.reason,'') END)) FROM shared_access_findings f
 LEFT JOIN risk_cases c ON c.case_id=f.case_id LEFT JOIN enforcement_actions a ON a.action_id=f.action_id
 WHERE f.observation_id=shared_behavior_observations.observation_id),'{}'::jsonb)`

func findingFilter(value string) (string, bool) {
	switch value {
	case "", "outlets":
		return "true", true
	case "accounts":
		return "f.account_id<>''", true
	case "router_pending", "unattributed", "exempt", "confirmed":
		return "f.outcome='" + value + "'", true
	case "router":
		return "f.outcome='confirmed' AND f.basis='authenticated_router'", true
	case "multiple":
		return "f.outcome='confirmed' AND f.basis='ieee1905_association'", true
	case "cases":
		return "EXISTS(SELECT 1 FROM risk_cases c WHERE c.case_id=f.case_id)", true
	case "actions":
		return "EXISTS(SELECT 1 FROM enforcement_actions a WHERE a.action_id=f.action_id AND a.mode='record_only')", true
	}
	return "", false
}

func (s *DBStore) PendingSharedFindings(ctx context.Context) ([]sharedaccess.BehaviorAssessment, error) {
	rows, err := s.pg.db.QueryContext(ctx, `SELECT o.observation,f.case_id FROM shared_access_findings f JOIN shared_behavior_observations o USING(observation_id)
 WHERE f.case_pending ORDER BY f.observed_at,f.observation_id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []sharedaccess.BehaviorAssessment
	for rows.Next() {
		var raw []byte
		var id string
		var item sharedaccess.BehaviorAssessment
		if err = rows.Scan(&raw, &id); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		item.CaseID = id
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *DBStore) SharedFindingReport(ctx context.Context, from, to time.Time) (SharedBehaviorReport, error) {
	return s.pg.sharedFindingReport(ctx, from, to)
}
func (s *PostgresStore) sharedFindingReport(ctx context.Context, from, to time.Time) (SharedBehaviorReport, error) {
	r := SharedBehaviorReport{From: from, AsOf: to}
	// Restrict to the report window before checking whether the same outlet ever
	// acquired an account. Keep the existing any-failure count for its drilldown.
	err := s.db.QueryRowContext(ctx, `WITH findings AS (
 SELECT sensor_id,campus_id,access_domain,ip,account_id,outcome,basis,reason,case_id,action_id,
 bool_or(account_id<>'') OVER (PARTITION BY sensor_id,campus_id,access_domain,ip) AS attributed
 FROM shared_access_findings WHERE observed_at >= $1 AND observed_at < $2)
 SELECT count(DISTINCT (f.sensor_id,f.campus_id,f.access_domain,f.ip)),
 count(DISTINCT nullif(f.account_id,'')),count(DISTINCT (f.sensor_id,f.campus_id,f.access_domain,f.ip)) FILTER(WHERE f.outcome='unattributed'),
 count(DISTINCT f.account_id) FILTER(WHERE f.outcome='router_pending'),count(DISTINCT f.account_id) FILTER(WHERE f.outcome='exempt'),
 count(DISTINCT f.account_id) FILTER(WHERE f.outcome='confirmed'),
 count(DISTINCT f.account_id) FILTER(WHERE f.outcome='confirmed' AND f.basis='authenticated_router'),
 count(DISTINCT f.account_id) FILTER(WHERE f.outcome='confirmed' AND f.basis='ieee1905_association'),
 count(DISTINCT c.case_id),count(DISTINCT a.action_id),count(*) FILTER(WHERE f.outcome IN ('candidate','unattributed','router_pending')),
 count(DISTINCT (f.sensor_id,f.campus_id,f.access_domain,f.ip)) FILTER(WHERE NOT f.attributed AND f.outcome='unattributed' AND f.reason IN ('`+outletUncovered+`','`+outletChangesPending+`','`+outletIndexPending+`')),
 count(DISTINCT (f.sensor_id,f.campus_id,f.access_domain,f.ip)) FILTER(WHERE NOT f.attributed AND f.outcome='unattributed' AND f.reason IN ('`+outletMissingBinding+`','`+outletBindingConflict+`')),
 count(DISTINCT (f.sensor_id,f.campus_id,f.access_domain,f.ip)) FILTER(WHERE NOT f.attributed AND f.outcome='unattributed' AND f.reason='`+outletMirrorMismatch+`')
 FROM findings f LEFT JOIN risk_cases c ON f.case_id<>'' AND c.case_id=f.case_id
 LEFT JOIN enforcement_actions a ON f.action_id<>'' AND a.action_id=f.action_id AND a.mode='record_only'`, from, to).Scan(&r.Outlets, &r.Accounts, &r.Unattributed, &r.RouterPending, &r.Exempt, &r.Confirmed, &r.Router, &r.Multiple, &r.Cases, &r.Actions, &r.PendingReview, &r.CoverageGapOutlets, &r.MissingBindingOutlets, &r.MirrorMismatchOutlets)
	return r, err
}
