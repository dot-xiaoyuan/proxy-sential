package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
)

type RouterQuery struct {
	Keyword        string
	IP             string
	MAC            string
	VLAN           string
	Brand          string
	Model          string
	Role           string
	Status         string
	Source         string
	ConfidenceMin  *int
	ConfidenceMax  *int
	FirstSeenFrom  string
	FirstSeenTo    string
	LastSeenFrom   string
	LastSeenTo     string
	Infrastructure *bool
	Limit          int
	Cursor         int
}

type RouterAssessmentPage struct {
	Items []evidence.RouterAssessment `json:"items"`
	Page  Page                        `json:"page"`
}

type RouterAssessmentHistory struct {
	Status      string   `json:"status"`
	Confidence  int      `json:"confidence"`
	RuleVersion string   `json:"rule_version"`
	ChangedAt   string   `json:"changed_at"`
	Conflicts   []string `json:"conflicts"`
}

type RouterObservationDetail struct {
	evidence.RouterAssessment
	History []RouterAssessmentHistory `json:"history"`
}

type RouterObservationReader interface {
	ListRouterObservations(context.Context, RouterQuery) (RouterAssessmentPage, error)
	GetRouterObservation(context.Context, string) (RouterObservationDetail, bool, error)
}

type RouterObservationSummaryReader interface {
	RouterObservationSummaries(context.Context, []string) (map[string]evidence.RouterAssessment, error)
}

type RouterObservationWriter interface {
	WriteRouterObservations(context.Context, evidence.RouterResult) error
}

func (s *PostgresStore) WriteRouterObservations(ctx context.Context, result evidence.RouterResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	config, _ := json.Marshal(fingerprint.DefaultRouterRuleSet())
	if _, err = tx.ExecContext(ctx, `UPDATE router_rule_versions SET active=false WHERE active AND version<>$1`, result.RuleVersion); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO router_rule_versions(version,active,config) VALUES($1,true,$2) ON CONFLICT(version) DO UPDATE SET active=true,config=EXCLUDED.config`, result.RuleVersion, config); err != nil {
		return err
	}
	touched := map[string]bool{}
	for _, item := range result.Evidence {
		if item.AssessmentID != "" {
			touched[item.AssessmentID] = true
		}
		data, _ := json.Marshal(item)
		_, err = tx.ExecContext(ctx, `INSERT INTO router_evidence_facts(evidence_id,assessment_id,endpoint_id,ip,mac,vlan,source,source_family,kind,rule_id,rule_version,score,conflict,exclusion,first_seen,last_seen,expires_at,data)
VALUES($1,$2,$3,NULLIF($4,'')::inet,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::timestamptz,$16::timestamptz,$17::timestamptz,$18)
ON CONFLICT(evidence_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,ip=EXCLUDED.ip,mac=EXCLUDED.mac,vlan=EXCLUDED.vlan,last_seen=GREATEST(router_evidence_facts.last_seen,EXCLUDED.last_seen),expires_at=GREATEST(router_evidence_facts.expires_at,EXCLUDED.expires_at),data=EXCLUDED.data`, item.EvidenceID, item.AssessmentID, item.EndpointID, item.IP, item.MAC, item.VLAN, item.Source, item.SourceFamily, item.Kind, item.RuleID, item.RuleVersion, item.Score, item.Conflict, item.Exclusion, item.FirstSeen, item.LastSeen, item.ExpiresAt, data)
		if err != nil {
			return err
		}
	}
	for _, item := range result.Assessments {
		if item.AssessmentID != "" {
			touched[item.AssessmentID] = true
		}
	}
	for assessmentID := range touched {
		rows, queryErr := tx.QueryContext(ctx, `SELECT data FROM router_evidence_facts
WHERE assessment_id=$1 AND kind<>'confirmed_router' AND expires_at>now()
ORDER BY last_seen,evidence_id`, assessmentID)
		if queryErr != nil {
			return queryErr
		}
		facts := []evidence.RouterEvidence{}
		for rows.Next() {
			var raw []byte
			if queryErr = rows.Scan(&raw); queryErr != nil {
				rows.Close()
				return queryErr
			}
			var fact evidence.RouterEvidence
			if queryErr = json.Unmarshal(raw, &fact); queryErr != nil {
				rows.Close()
				return queryErr
			}
			facts = append(facts, fact)
		}
		queryErr = rows.Err()
		rows.Close()
		if queryErr != nil {
			return queryErr
		}
		item, present := evidence.AggregateRouterEvidence(facts, fingerprint.DefaultRouterRuleSet(), time.Now().UTC())
		if !present {
			continue
		}
		vlans := item.VLANs
		if vlans == nil {
			vlans = []string{}
		}
		sources := item.Sources
		if sources == nil {
			sources = []string{}
		}
		data, _ := json.Marshal(item)
		conflicts, _ := json.Marshal(item.Conflicts)
		_, err = tx.ExecContext(ctx, `INSERT INTO router_assessments(assessment_id,endpoint_id,ip,mac,vlans,brand,series,model,role,status,confidence,sources,infrastructure,brand_reference_only,ambiguous,rule_version,first_seen,last_seen,expires_at,assessment)
VALUES($1,$2,NULLIF($3,'')::inet,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::timestamptz,$18::timestamptz,$19::timestamptz,$20)
ON CONFLICT(assessment_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,ip=EXCLUDED.ip,mac=EXCLUDED.mac,vlans=EXCLUDED.vlans,brand=EXCLUDED.brand,series=EXCLUDED.series,model=EXCLUDED.model,role=EXCLUDED.role,status=EXCLUDED.status,confidence=EXCLUDED.confidence,sources=EXCLUDED.sources,infrastructure=EXCLUDED.infrastructure,brand_reference_only=EXCLUDED.brand_reference_only,ambiguous=EXCLUDED.ambiguous,rule_version=EXCLUDED.rule_version,first_seen=LEAST(router_assessments.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(router_assessments.last_seen,EXCLUDED.last_seen),expires_at=EXCLUDED.expires_at,assessment=EXCLUDED.assessment,updated_at=now()`, item.AssessmentID, item.EndpointID, item.IP, item.MAC, vlans, item.Brand, item.Series, item.Model, item.Role, item.Status, item.Confidence, sources, item.Infrastructure, item.BrandReferenceOnly, item.Ambiguous, item.RuleVersion, item.FirstSeen, item.LastSeen, item.ExpiresAt, data)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO router_assessment_history(assessment_id,status,confidence,rule_version,changed_at,conflicts)
SELECT $1,$2,$3,$4,$5::timestamptz,$6 WHERE NOT EXISTS(
 SELECT 1 FROM (SELECT status,confidence,rule_version FROM router_assessment_history WHERE assessment_id=$1 ORDER BY changed_at DESC,history_id DESC LIMIT 1) latest
WHERE latest.status=$2 AND latest.confidence=$3 AND latest.rule_version=$4)`, item.AssessmentID, item.Status, item.Confidence, item.RuleVersion, item.LastSeen, conflicts)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) ListRouterObservations(ctx context.Context, query RouterQuery) (RouterAssessmentPage, error) {
	if query.Limit <= 0 {
		query.Limit = 20
	}
	where, args, err := routerWhere(query)
	if err != nil {
		return RouterAssessmentPage{}, err
	}
	args = append(args, query.Limit, query.Cursor)
	// A device may first be observed by MAC and later gain an endpoint identity.
	// Keep both durable assessments for auditability, but expose one current row
	// per physical device so the operator does not see the same router twice.
	rows, err := s.db.QueryContext(ctx, `WITH filtered AS (
 SELECT *,CASE
  WHEN mac<>'' THEN 'mac:'||lower(mac)
  WHEN endpoint_id<>'' THEN 'endpoint:'||endpoint_id
  WHEN ip IS NOT NULL THEN 'ip:'||host(ip)||':vlans:'||array_to_string(vlans,',')
  ELSE 'assessment:'||assessment_id
 END AS device_key
 FROM router_assessments `+where+`
), ranked AS (
 SELECT assessment,confidence,last_seen,assessment_id,
  count(*) OVER(PARTITION BY device_key) AS merged_records,
  row_number() OVER(PARTITION BY device_key ORDER BY
   CASE status WHEN 'confirmed' THEN 3 WHEN 'likely' THEN 2 ELSE 1 END DESC,
   confidence DESC,(endpoint_id<>'') DESC,last_seen DESC,assessment_id) AS device_rank
 FROM filtered
), devices AS (
 SELECT assessment,confidence,last_seen,assessment_id,merged_records FROM ranked WHERE device_rank=1
)
SELECT assessment,merged_records,count(*) OVER() FROM devices`+fmt.Sprintf(` ORDER BY confidence DESC,last_seen DESC,assessment_id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return RouterAssessmentPage{}, err
	}
	defer rows.Close()
	page := RouterAssessmentPage{Items: []evidence.RouterAssessment{}, Page: Page{Limit: query.Limit}}
	for rows.Next() {
		var raw []byte
		var mergedRecords int
		if err = rows.Scan(&raw, &mergedRecords, &page.Page.Total); err != nil {
			return page, err
		}
		var item evidence.RouterAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return page, err
		}
		item.Evidence = nil
		item.MergedRecords = mergedRecords
		page.Items = append(page.Items, item)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if query.Cursor+len(page.Items) < page.Page.Total {
		next := fmt.Sprint(query.Cursor + len(page.Items))
		page.Page.NextCursor = &next
	}
	return page, nil
}

func (s *PostgresStore) GetRouterObservation(ctx context.Context, id string) (RouterObservationDetail, bool, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT assessment FROM router_assessments WHERE assessment_id=$1`, id).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return RouterObservationDetail{}, false, nil
		}
		return RouterObservationDetail{}, false, err
	}
	var result RouterObservationDetail
	if err := json.Unmarshal(raw, &result.RouterAssessment); err != nil {
		return RouterObservationDetail{}, false, err
	}
	// Historical and expired facts remain durable, but the current device page
	// should not repeat evidence from every previous ruleset replay.
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM router_evidence_facts WHERE assessment_id=$1 AND expires_at>now() ORDER BY last_seen DESC,evidence_id`, id)
	if err != nil {
		return RouterObservationDetail{}, false, err
	}
	result.Evidence = []evidence.RouterEvidence{}
	for rows.Next() {
		var itemRaw []byte
		if err = rows.Scan(&itemRaw); err != nil {
			rows.Close()
			return RouterObservationDetail{}, false, err
		}
		var item evidence.RouterEvidence
		if err = json.Unmarshal(itemRaw, &item); err != nil {
			rows.Close()
			return RouterObservationDetail{}, false, err
		}
		result.Evidence = append(result.Evidence, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return RouterObservationDetail{}, false, err
	}
	rows.Close()
	historyRows, err := s.db.QueryContext(ctx, `SELECT status,confidence,rule_version,changed_at,conflicts FROM router_assessment_history WHERE assessment_id=$1 ORDER BY changed_at,history_id`, id)
	if err != nil {
		return RouterObservationDetail{}, false, err
	}
	defer historyRows.Close()
	for historyRows.Next() {
		var item RouterAssessmentHistory
		var at time.Time
		var conflicts []byte
		if err = historyRows.Scan(&item.Status, &item.Confidence, &item.RuleVersion, &at, &conflicts); err != nil {
			return RouterObservationDetail{}, false, err
		}
		item.ChangedAt = at.UTC().Format(time.RFC3339Nano)
		_ = json.Unmarshal(conflicts, &item.Conflicts)
		result.History = append(result.History, item)
	}
	return result, true, historyRows.Err()
}

func (s *PostgresStore) RouterObservationSummaries(ctx context.Context, endpointIDs []string) (map[string]evidence.RouterAssessment, error) {
	result := map[string]evidence.RouterAssessment{}
	if len(endpointIDs) == 0 {
		return result, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ON(endpoint_id) endpoint_id,assessment FROM router_assessments r WHERE endpoint_id=ANY($1) AND expires_at>now() AND ip IS NOT NULL AND role='router' AND status IN('likely','confirmed') AND brand_reference_only=false
AND EXISTS(SELECT 1 FROM router_evidence_facts f WHERE f.assessment_id=r.assessment_id AND f.expires_at>now() AND f.conflict=false AND f.exclusion=false AND COALESCE(f.data->>'brand_reference_only','false')='false' AND f.data->>'role'='router')
AND NOT EXISTS(SELECT 1 FROM labels review WHERE review.target_type='router_ip' AND review.target_id=host(r.ip) AND review.label='not_router' AND NOT EXISTS(SELECT 1 FROM labels newer WHERE newer.target_type='router_ip' AND newer.target_id=review.target_id AND (newer.created_at,newer.label_id)>(review.created_at,review.label_id)))
ORDER BY endpoint_id,confidence DESC,last_seen DESC`, endpointIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var endpointID string
		var raw []byte
		if err = rows.Scan(&endpointID, &raw); err != nil {
			return nil, err
		}
		var item evidence.RouterAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		item.Evidence = nil
		result[endpointID] = item
	}
	return result, rows.Err()
}

func routerWhere(query RouterQuery) (string, []any, error) {
	// The operator-facing router list is not a generic vendor/device inventory.
	// Keep raw and excluded observations durable for audit, but do not surface
	// address-less discovery frames or brand-only endpoint hints as routers.
	clauses, args := []string{"expires_at>now()", "ip IS NOT NULL", "brand_reference_only=false"}, []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if value := strings.TrimSpace(query.Keyword); value != "" {
		args = append(args, value)
		position := len(args)
		placeholder := fmt.Sprintf("$%d", position)
		clauses = append(clauses, `(assessment_id ILIKE '%'||`+placeholder+`||'%' OR endpoint_id ILIKE '%'||`+placeholder+`||'%' OR host(ip) ILIKE '%'||`+placeholder+`||'%' OR mac ILIKE '%'||`+placeholder+`||'%' OR brand ILIKE '%'||`+placeholder+`||'%' OR series ILIKE '%'||`+placeholder+`||'%' OR model ILIKE '%'||`+placeholder+`||'%')`)
	}
	if strings.TrimSpace(query.Role) == "" {
		clauses = append(clauses, "role='router'")
		clauses = append(clauses, "EXISTS(SELECT 1 FROM router_evidence_facts active_router_fact WHERE active_router_fact.assessment_id=router_assessments.assessment_id AND active_router_fact.expires_at>now() AND active_router_fact.conflict=false AND active_router_fact.exclusion=false AND COALESCE(active_router_fact.data->>'brand_reference_only','false')='false' AND active_router_fact.data->>'role'='router')")
		clauses = append(clauses, "NOT EXISTS(SELECT 1 FROM labels router_review WHERE router_review.target_type='router_ip' AND router_review.target_id=host(ip) AND router_review.label='not_router' AND NOT EXISTS(SELECT 1 FROM labels newer_router_review WHERE newer_router_review.target_type='router_ip' AND newer_router_review.target_id=router_review.target_id AND (newer_router_review.created_at,newer_router_review.label_id)>(router_review.created_at,router_review.label_id)))")
	}
	if strings.TrimSpace(query.Status) == "" {
		clauses = append(clauses, "status IN('likely','confirmed')")
	}
	for _, item := range []struct{ value, clause string }{{query.IP, `ip=$%d::inet`}, {strings.ToLower(query.MAC), `lower(mac)=$%d`}, {query.VLAN, `$%d=ANY(vlans)`}, {query.Brand, `lower(brand)=lower($%d)`}, {query.Model, `lower(model)=lower($%d)`}, {query.Role, `role=$%d`}, {query.Status, `status=$%d`}, {query.Source, `$%d=ANY(sources)`}} {
		if strings.TrimSpace(item.value) != "" {
			add(item.clause, strings.TrimSpace(item.value))
		}
	}
	if query.ConfidenceMin != nil {
		add(`confidence >= $%d`, *query.ConfidenceMin)
	}
	if query.ConfidenceMax != nil {
		add(`confidence <= $%d`, *query.ConfidenceMax)
	}
	if query.Infrastructure != nil {
		add(`infrastructure=$%d`, *query.Infrastructure)
	}
	for _, item := range []struct{ value, clause string }{{query.FirstSeenFrom, `first_seen >= $%d::timestamptz`}, {query.FirstSeenTo, `first_seen <= $%d::timestamptz`}, {query.LastSeenFrom, `last_seen >= $%d::timestamptz`}, {query.LastSeenTo, `last_seen <= $%d::timestamptz`}} {
		if item.value == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, item.value); err != nil {
			return "", nil, fmt.Errorf("invalid router timestamp %q", item.value)
		}
		add(item.clause, item.value)
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func (s *DBStore) WriteRouterObservations(ctx context.Context, result evidence.RouterResult) error {
	return s.pg.WriteRouterObservations(ctx, result)
}

func (s *DBStore) ListRouterObservations(ctx context.Context, query RouterQuery) (RouterAssessmentPage, error) {
	return s.pg.ListRouterObservations(ctx, query)
}

func (s *DBStore) GetRouterObservation(ctx context.Context, id string) (RouterObservationDetail, bool, error) {
	return s.pg.GetRouterObservation(ctx, id)
}

func (s *DBStore) RouterObservationSummaries(ctx context.Context, endpointIDs []string) (map[string]evidence.RouterAssessment, error) {
	return s.pg.RouterObservationSummaries(ctx, endpointIDs)
}

func (s *DBStore) ResolveDeviceAt(ctx context.Context, observation DomainObservation) (IdentityAttribution, bool, error) {
	return s.pg.ResolveDeviceAt(ctx, observation)
}
