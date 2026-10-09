package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
)

type RouterQuery struct {
	Keyword           string
	IP                string
	MAC               string
	VLAN              string
	Brand             string
	Model             string
	Role              string
	Status            string
	IncludeCandidates bool
	Source            string
	ConfidenceMin     *int
	ConfidenceMax     *int
	FirstSeenFrom     string
	FirstSeenTo       string
	LastSeenFrom      string
	LastSeenTo        string
	Infrastructure    *bool
	HasAuthBinding    *bool
	Limit             int
	Cursor            int
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
	Current bool                      `json:"current"`
	History []RouterAssessmentHistory `json:"history"`
}

// The JSON projection preserves source details, while relational timestamps
// preserve monotonic discovery bounds and explicit retirement. Every current
// read model uses the same authoritative bounds.
type routerObservationTimes struct{ first, last, expires time.Time }

func (t routerObservationTimes) applyAssessment(item *evidence.RouterAssessment) {
	item.FirstSeen = t.first.UTC().Format(time.RFC3339Nano)
	item.LastSeen = t.last.UTC().Format(time.RFC3339Nano)
	item.ExpiresAt = t.expires.UTC().Format(time.RFC3339Nano)
}
func (t routerObservationTimes) applyEvidence(item *evidence.RouterEvidence) {
	item.FirstSeen = t.first.UTC().Format(time.RFC3339Nano)
	item.LastSeen = t.last.UTC().Format(time.RFC3339Nano)
	item.ExpiresAt = t.expires.UTC().Format(time.RFC3339Nano)
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
ON CONFLICT(evidence_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,ip=EXCLUDED.ip,mac=EXCLUDED.mac,vlan=EXCLUDED.vlan,source=EXCLUDED.source,source_family=EXCLUDED.source_family,kind=EXCLUDED.kind,rule_id=EXCLUDED.rule_id,rule_version=EXCLUDED.rule_version,score=EXCLUDED.score,conflict=EXCLUDED.conflict,exclusion=EXCLUDED.exclusion,first_seen=LEAST(router_evidence_facts.first_seen,EXCLUDED.first_seen),last_seen=EXCLUDED.last_seen,expires_at=CASE WHEN EXCLUDED.source_family='shared_gateway_behavior' THEN EXCLUDED.expires_at ELSE GREATEST(router_evidence_facts.expires_at,EXCLUDED.expires_at) END,data=EXCLUDED.data
WHERE EXCLUDED.last_seen>=router_evidence_facts.last_seen`, item.EvidenceID, item.AssessmentID, item.EndpointID, item.IP, item.MAC, item.VLAN, item.Source, item.SourceFamily, item.Kind, item.RuleID, item.RuleVersion, item.Score, item.Conflict, item.Exclusion, item.FirstSeen, item.LastSeen, item.ExpiresAt, data)
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
		if err = rebuildRouterAssessment(ctx, tx, assessmentID, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// rebuildRouterAssessment is shared by new facts and complete-window retirement.
// Both paths update the durable current projection and its audit in one transaction.
func rebuildRouterAssessment(ctx context.Context, tx *sql.Tx, assessmentID string, at time.Time) error {
	var err error
	rows, queryErr := tx.QueryContext(ctx, `SELECT data,first_seen,last_seen,expires_at FROM router_evidence_facts
WHERE assessment_id=$1 AND kind<>'confirmed_router' AND expires_at>now()
ORDER BY last_seen,evidence_id`, assessmentID)
	if queryErr != nil {
		return queryErr
	}
	facts := []evidence.RouterEvidence{}
	for rows.Next() {
		var raw []byte
		var times routerObservationTimes
		if queryErr = rows.Scan(&raw, &times.first, &times.last, &times.expires); queryErr != nil {
			rows.Close()
			return queryErr
		}
		var fact evidence.RouterEvidence
		if queryErr = json.Unmarshal(raw, &fact); queryErr != nil {
			rows.Close()
			return queryErr
		}
		times.applyEvidence(&fact)
		facts = append(facts, fact)
	}
	queryErr = rows.Err()
	rows.Close()
	if queryErr != nil {
		return queryErr
	}
	item, present := evidence.AggregateRouterEvidence(facts, fingerprint.DefaultRouterRuleSet(), at)
	if !present {
		// Retain the original facts and prior verdicts for audit; retire only the
		// current projection when its last eligible role fact is withdrawn.
		if _, err := tx.ExecContext(ctx, `UPDATE router_assessments SET expires_at=LEAST(expires_at,$2),assessment=jsonb_set(assessment,'{expires_at}',to_jsonb($2::timestamptz)),updated_at=$2 WHERE assessment_id=$1`, assessmentID, at); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO router_assessment_history(assessment_id,status,confidence,rule_version,changed_at,conflicts) SELECT assessment_id,status,confidence,rule_version,$2,'["shared_gateway_window_retired"]'::jsonb FROM router_assessments WHERE assessment_id=$1`, assessmentID, at)
		return err
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
ON CONFLICT(assessment_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,ip=EXCLUDED.ip,mac=EXCLUDED.mac,vlans=EXCLUDED.vlans,brand=EXCLUDED.brand,series=EXCLUDED.series,model=EXCLUDED.model,role=EXCLUDED.role,status=EXCLUDED.status,confidence=EXCLUDED.confidence,sources=EXCLUDED.sources,infrastructure=EXCLUDED.infrastructure,brand_reference_only=EXCLUDED.brand_reference_only,ambiguous=EXCLUDED.ambiguous,rule_version=EXCLUDED.rule_version,first_seen=LEAST(router_assessments.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(router_assessments.last_seen,EXCLUDED.last_seen),expires_at=EXCLUDED.expires_at,assessment=jsonb_set(jsonb_set(jsonb_set(EXCLUDED.assessment,'{first_seen}',to_jsonb(LEAST(router_assessments.first_seen,EXCLUDED.first_seen))),'{last_seen}',to_jsonb(GREATEST(router_assessments.last_seen,EXCLUDED.last_seen))),'{expires_at}',to_jsonb(EXCLUDED.expires_at)),updated_at=now()`, item.AssessmentID, item.EndpointID, item.IP, item.MAC, vlans, item.Brand, item.Series, item.Model, item.Role, item.Status, item.Confidence, sources, item.Infrastructure, item.BrandReferenceOnly, item.Ambiguous, item.RuleVersion, item.FirstSeen, item.LastSeen, item.ExpiresAt, data)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO router_assessment_history(assessment_id,status,confidence,rule_version,changed_at,conflicts)
SELECT $1,$2,$3,$4,$5::timestamptz,$6 WHERE NOT EXISTS(
 SELECT 1 FROM (SELECT status,confidence,rule_version,conflicts FROM router_assessment_history WHERE assessment_id=$1 ORDER BY history_id DESC LIMIT 1) latest
WHERE latest.status=$2 AND latest.confidence=$3 AND latest.rule_version=$4 AND latest.conflicts=$6::jsonb)`, item.AssessmentID, item.Status, item.Confidence, item.RuleVersion, at, conflicts)
	if err != nil {
		return err
	}
	return nil
}

// Refresh only verdicts whose published score still references an expired fact.
// The small batch runs in the recognition worker, including periods with no new
// traffic, so a surviving weak fact cannot keep yesterday's strong score alive.
func (s *PostgresStore) refreshExpiredRouterAssessments(ctx context.Context, limit int) (int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT r.assessment_id FROM router_assessments r
WHERE r.expires_at>now() AND r.role IN('router','ap') AND EXISTS(
 SELECT 1 FROM jsonb_array_elements(COALESCE(r.assessment->'score_components','[]'::jsonb)) component
 JOIN router_evidence_facts f ON f.evidence_id=component->>'evidence_id' AND f.assessment_id=r.assessment_id
 WHERE f.expires_at<=now()
) ORDER BY r.expires_at,r.assessment_id FOR UPDATE OF r SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err = rebuildRouterAssessment(ctx, tx, id, time.Now().UTC()); err != nil {
			return 0, err
		}
	}
	return len(ids), tx.Commit()
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
 SELECT assessment,confidence,first_seen,last_seen,expires_at,assessment_id,
  count(*) OVER(PARTITION BY device_key) AS merged_records,
  row_number() OVER(PARTITION BY device_key ORDER BY
   CASE status WHEN 'confirmed' THEN 3 WHEN 'likely' THEN 2 ELSE 1 END DESC,
   confidence DESC,(endpoint_id<>'') DESC,last_seen DESC,assessment_id) AS device_rank
 FROM filtered
), devices AS (
 SELECT assessment,confidence,first_seen,last_seen,expires_at,assessment_id,merged_records FROM ranked WHERE device_rank=1
)
SELECT assessment,merged_records,count(*) OVER(),first_seen,last_seen,expires_at FROM devices`+fmt.Sprintf(` ORDER BY confidence DESC,last_seen DESC,assessment_id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return RouterAssessmentPage{}, err
	}
	defer rows.Close()
	page := RouterAssessmentPage{Items: []evidence.RouterAssessment{}, Page: Page{Limit: query.Limit}}
	for rows.Next() {
		var raw []byte
		var mergedRecords int
		var times routerObservationTimes
		if err = rows.Scan(&raw, &mergedRecords, &page.Page.Total, &times.first, &times.last, &times.expires); err != nil {
			return page, err
		}
		var item evidence.RouterAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return page, err
		}
		item.Evidence = nil
		item.MergedRecords = mergedRecords
		times.applyAssessment(&item)
		page.Items = append(page.Items, item)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if err = s.attachRouterAuthBindings(ctx, page.Items); err != nil {
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
	var times routerObservationTimes
	if err := s.db.QueryRowContext(ctx, `SELECT assessment,first_seen,last_seen,expires_at FROM router_assessments WHERE assessment_id=$1`, id).Scan(&raw, &times.first, &times.last, &times.expires); err != nil {
		if err == sql.ErrNoRows {
			return RouterObservationDetail{}, false, nil
		}
		return RouterObservationDetail{}, false, err
	}
	var result RouterObservationDetail
	if err := json.Unmarshal(raw, &result.RouterAssessment); err != nil {
		return RouterObservationDetail{}, false, err
	}
	times.applyAssessment(&result.RouterAssessment)
	result.Current = times.expires.After(time.Now().UTC())
	// Historical and expired facts remain durable, but the current device page
	// should not repeat evidence from every previous ruleset replay.
	rows, err := s.db.QueryContext(ctx, `SELECT data,first_seen,last_seen,expires_at FROM router_evidence_facts WHERE assessment_id=$1 AND expires_at>now() ORDER BY last_seen DESC,evidence_id`, id)
	if err != nil {
		return RouterObservationDetail{}, false, err
	}
	result.Evidence = []evidence.RouterEvidence{}
	for rows.Next() {
		var itemRaw []byte
		var factTimes routerObservationTimes
		if err = rows.Scan(&itemRaw, &factTimes.first, &factTimes.last, &factTimes.expires); err != nil {
			rows.Close()
			return RouterObservationDetail{}, false, err
		}
		var item evidence.RouterEvidence
		if err = json.Unmarshal(itemRaw, &item); err != nil {
			rows.Close()
			return RouterObservationDetail{}, false, err
		}
		factTimes.applyEvidence(&item)
		result.Evidence = append(result.Evidence, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return RouterObservationDetail{}, false, err
	}
	rows.Close()
	result.Current = result.Current && len(result.Evidence) > 0
	if result.Current {
		items := []evidence.RouterAssessment{result.RouterAssessment}
		if err = s.attachRouterAuthBindings(ctx, items); err != nil {
			return RouterObservationDetail{}, false, err
		}
		result.AuthBindings = items[0].AuthBindings
	}
	historyRows, err := s.db.QueryContext(ctx, `SELECT status,confidence,rule_version,changed_at,conflicts FROM router_assessment_history WHERE assessment_id=$1 ORDER BY history_id`, id)
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

type routerAuthSession struct {
	session   AccountSession
	confirmed string
}

// attachRouterAuthBindings performs one bounded query per page and only links
// exact MAC or endpoint identities. IP, VLAN and time proximity are never
// considered, which prevents every private 192.168.1.1 observation from being
// attributed to the same authenticated account.
func (s *PostgresStore) attachRouterAuthBindings(ctx context.Context, items []evidence.RouterAssessment) error {
	macs, endpoints := []string{}, []string{}
	seenMAC, seenEndpoint := map[string]bool{}, map[string]bool{}
	for _, item := range items {
		if mac := normalizedRouterAuthMAC(item.MAC); mac != "" && !seenMAC[mac] {
			seenMAC[mac], macs = true, append(macs, mac)
		}
		if endpoint := strings.TrimSpace(item.EndpointID); endpoint != "" && !seenEndpoint[endpoint] {
			seenEndpoint[endpoint], endpoints = true, append(endpoints, endpoint)
		}
	}
	if len(macs) == 0 && len(endpoints) == 0 {
		return nil
	}
	sessions, err := s.currentAuthSessionsForIdentities(ctx, macs, endpoints)
	if err != nil {
		return err
	}
	for index := range items {
		items[index].AuthBindings = routerBindingsForAssessment(items[index], sessions)
	}
	return nil
}

func (s *PostgresStore) currentAuthSessionsForIdentities(ctx context.Context, macs, endpoints []string) ([]routerAuthSession, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT document,confirmed_at FROM account_identity_session_projection p
JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain)
WHERE COALESCE(document->>'ended_at','')=''
AND src.observed_at >= now()-make_interval(secs=>GREATEST(60,LEAST(86400,COALESCE(NULLIF(document->>'reconcile_interval_seconds','')::int,1800)))*3)
AND ((document->>'endpoint_id'=ANY($2::text[]) AND document->>'endpoint_id'<>'') OR regexp_replace(lower(COALESCE(document->>'mac','')),'[^0-9a-f]','','g')=ANY($1::text[]))
UNION ALL
SELECT to_jsonb(s)||COALESCE(s.policy_metadata,'{}'::jsonb),s.updated_at FROM account_sessions s
WHERE s.ended_at IS NULL AND s.updated_at>=now()-interval '90 minutes'
AND ((s.endpoint_id=ANY($2::text[]) AND s.endpoint_id<>'') OR regexp_replace(lower(COALESCE(s.mac,'')),'[^0-9a-f]','','g')=ANY($1::text[]))`, macs, endpoints)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := []routerAuthSession{}
	for rows.Next() {
		var raw []byte
		var confirmed time.Time
		if err = rows.Scan(&raw, &confirmed); err != nil {
			return nil, err
		}
		var session AccountSession
		if err = json.Unmarshal(raw, &session); err != nil {
			return nil, err
		}
		if session.SessionID == "" || session.AccountID == "" || session.Source == "" || session.EndedAt != "" {
			continue
		}
		sessions = append(sessions, routerAuthSession{session: session, confirmed: confirmed.UTC().Format(time.RFC3339Nano)})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
}

func routerBindingsForAssessment(item evidence.RouterAssessment, sessions []routerAuthSession) []evidence.RouterAuthBinding {
	type groupedBinding struct {
		binding evidence.RouterAuthBinding
		ips     map[string]bool
	}
	groups := map[string]*groupedBinding{}
	itemMAC := normalizedRouterAuthMAC(item.MAC)
	itemEndpoint := strings.TrimSpace(item.EndpointID)
	for _, candidate := range sessions {
		session := candidate.session
		basis := ""
		if itemEndpoint != "" && strings.TrimSpace(session.EndpointID) == itemEndpoint {
			basis = "exact_endpoint"
		} else if itemMAC != "" && normalizedRouterAuthMAC(session.MAC) == itemMAC {
			basis = "exact_mac"
		}
		if basis == "" {
			continue
		}
		key := strings.Join([]string{session.Source, session.SessionID, session.AccountID}, "\x1f")
		group := groups[key]
		if group == nil {
			group = &groupedBinding{binding: evidence.RouterAuthBinding{SessionID: session.SessionID, AccountID: session.AccountID, MAC: session.MAC, VLAN: session.VLAN, NASIP: session.NASIP, AccessID: session.AccessID, Source: session.Source, MatchBasis: basis, StartedAt: session.StartedAt, LastConfirmedAt: firstNonEmpty(candidate.confirmed, session.LastConfirmedAt)}, ips: map[string]bool{}}
			groups[key] = group
		}
		if session.IP != "" {
			group.ips[session.IP] = true
		}
		if basis == "exact_endpoint" {
			group.binding.MatchBasis = basis
		}
		if candidate.confirmed > group.binding.LastConfirmedAt {
			group.binding.LastConfirmedAt = candidate.confirmed
		}
	}
	out := make([]evidence.RouterAuthBinding, 0, len(groups))
	for _, group := range groups {
		for ip := range group.ips {
			group.binding.AssignedIPs = append(group.binding.AssignedIPs, ip)
		}
		slices.Sort(group.binding.AssignedIPs)
		group.binding.Ambiguous = len(groups) > 1
		out = append(out, group.binding)
	}
	slices.SortFunc(out, func(a, b evidence.RouterAuthBinding) int {
		if a.Ambiguous != b.Ambiguous {
			if a.Ambiguous {
				return 1
			}
			return -1
		}
		if a.LastConfirmedAt != b.LastConfirmedAt {
			return strings.Compare(b.LastConfirmedAt, a.LastConfirmedAt)
		}
		return strings.Compare(a.SessionID, b.SessionID)
	})
	return out
}

func normalizedRouterAuthMAC(value string) string {
	var result strings.Builder
	for _, char := range strings.ToLower(value) {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') {
			result.WriteRune(char)
		}
	}
	if result.Len() != 12 {
		return ""
	}
	return result.String()
}

func (s *PostgresStore) RouterObservationSummaries(ctx context.Context, endpointIDs []string) (map[string]evidence.RouterAssessment, error) {
	result := map[string]evidence.RouterAssessment{}
	if len(endpointIDs) == 0 {
		return result, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ON(endpoint_id) endpoint_id,assessment,first_seen,last_seen,expires_at FROM router_assessments r WHERE endpoint_id=ANY($1) AND expires_at>now() AND ip IS NOT NULL AND role='router' AND status IN('likely','confirmed') AND brand_reference_only=false
AND EXISTS(SELECT 1 FROM router_evidence_facts f WHERE f.assessment_id=r.assessment_id AND f.expires_at>now() AND f.conflict=false AND f.exclusion=false AND COALESCE(f.data->>'brand_reference_only','false')='false' AND f.data->>'role'='router')
ORDER BY endpoint_id,confidence DESC,last_seen DESC`, endpointIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var endpointID string
		var raw []byte
		var times routerObservationTimes
		if err = rows.Scan(&endpointID, &raw, &times.first, &times.last, &times.expires); err != nil {
			return nil, err
		}
		var item evidence.RouterAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		item.Evidence = nil
		times.applyAssessment(&item)
		result[endpointID] = item
	}
	return result, rows.Err()
}

func routerWhere(query RouterQuery) (string, []any, error) {
	// The operator-facing router list is not a generic vendor/device inventory.
	// Keep raw and excluded observations durable for audit, but surface only
	// addressed routing or wireless-access devices backed by current role facts.
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
	role := strings.TrimSpace(query.Role)
	if role == "" {
		clauses = append(clauses, "role='router'")
		clauses = append(clauses, "EXISTS(SELECT 1 FROM router_evidence_facts active_router_fact WHERE active_router_fact.assessment_id=router_assessments.assessment_id AND active_router_fact.expires_at>now() AND active_router_fact.conflict=false AND active_router_fact.exclusion=false AND COALESCE(active_router_fact.data->>'brand_reference_only','false')='false' AND active_router_fact.data->>'role'='router')")
	} else if role == "router" || role == "ap" {
		factRole := "router"
		if role == "ap" {
			factRole = "ap"
		}
		clauses = append(clauses, "EXISTS(SELECT 1 FROM router_evidence_facts active_router_fact WHERE active_router_fact.assessment_id=router_assessments.assessment_id AND active_router_fact.expires_at>now() AND active_router_fact.conflict=false AND active_router_fact.exclusion=false AND COALESCE(active_router_fact.data->>'brand_reference_only','false')='false' AND active_router_fact.data->>'role'='"+factRole+"')")
	}
	if strings.TrimSpace(query.Status) == "" && !query.IncludeCandidates {
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
	if query.HasAuthBinding != nil {
		// These uncorrelated subqueries are planned as hashed membership sets.
		// Building the current exact-identity sets once is substantially cheaper
		// than probing both session tables for every router assessment.
		predicate := `((router_assessments.endpoint_id<>'' AND router_assessments.endpoint_id IN (
SELECT auth_projection.document->>'endpoint_id' FROM account_identity_session_projection auth_projection
JOIN account_identity_projection_sources auth_source USING(source,sensor_id,campus_id,access_domain)
WHERE COALESCE(auth_projection.document->>'ended_at','')='' AND COALESCE(auth_projection.document->>'endpoint_id','')<>''
AND auth_source.observed_at >= now()-make_interval(secs=>GREATEST(60,LEAST(86400,COALESCE(NULLIF(auth_projection.document->>'reconcile_interval_seconds','')::int,1800)))*3)
UNION
SELECT auth_session.endpoint_id FROM account_sessions auth_session
WHERE auth_session.ended_at IS NULL AND auth_session.updated_at>=now()-interval '90 minutes' AND COALESCE(auth_session.endpoint_id,'')<>''
)) OR (router_assessments.mac<>'' AND regexp_replace(lower(router_assessments.mac),'[^0-9a-f]','','g') IN (
SELECT regexp_replace(lower(COALESCE(auth_projection.document->>'mac','')),'[^0-9a-f]','','g') FROM account_identity_session_projection auth_projection
JOIN account_identity_projection_sources auth_source USING(source,sensor_id,campus_id,access_domain)
WHERE COALESCE(auth_projection.document->>'ended_at','')='' AND COALESCE(auth_projection.document->>'mac','')<>''
AND auth_source.observed_at >= now()-make_interval(secs=>GREATEST(60,LEAST(86400,COALESCE(NULLIF(auth_projection.document->>'reconcile_interval_seconds','')::int,1800)))*3)
UNION
SELECT regexp_replace(lower(COALESCE(auth_session.mac,'')),'[^0-9a-f]','','g') FROM account_sessions auth_session
WHERE auth_session.ended_at IS NULL AND auth_session.updated_at>=now()-interval '90 minutes' AND COALESCE(auth_session.mac,'')<>''
)))`
		if !*query.HasAuthBinding {
			predicate = "NOT " + predicate
		}
		clauses = append(clauses, predicate)
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
