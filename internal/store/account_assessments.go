package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const accountTagWindow = 7 * 24 * time.Hour

type AccountTagAssessment struct {
	AccountID         string   `json:"account_id"`
	TagType           string   `json:"tag_type"`
	AssessmentVersion string   `json:"assessment_version"`
	State             string   `json:"state"`
	EvidenceLevel     string   `json:"evidence_level"`
	SourceType        string   `json:"source_type"`
	Reason            string   `json:"reason"`
	EndpointIDs       []string `json:"endpoint_ids"`
	EvidenceIDs       []string `json:"evidence_ids"`
	RuleVersion       string   `json:"rule_version,omitempty"`
	RawScore          float64  `json:"-"`
	FirstSeen         string   `json:"first_seen"`
	LastSeen          string   `json:"last_seen"`
	ValidUntil        string   `json:"valid_until"`
	RecordedAt        string   `json:"recorded_at,omitempty"`
	ReviewState       string   `json:"review_state"`
}

type AccountAssessmentListItem struct {
	AccountID     string                 `json:"account_id"`
	Tags          []AccountTagAssessment `json:"tags"`
	EndpointCount int                    `json:"endpoint_count"`
	PrimaryReason string                 `json:"primary_reason"`
	ReviewState   string                 `json:"review_state"`
	LastAssessed  string                 `json:"last_assessed_at"`
}

type AccountAssessmentPage struct {
	Items []AccountAssessmentListItem `json:"items"`
	State string                      `json:"state"`
	AsOf  string                      `json:"as_of"`
	Page  Page                        `json:"page"`
}

type AccountAssessmentEndpoint struct {
	EndpointID    string `json:"endpoint_id"`
	PrimaryMAC    string `json:"primary_mac,omitempty"`
	Brand         string `json:"brand,omitempty"`
	Model         string `json:"model,omitempty"`
	DeviceType    string `json:"device_type,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
	EvidenceLevel string `json:"evidence_level"`
}

type AccountTagReview struct {
	ReviewID          string   `json:"review_id"`
	AccountID         string   `json:"account_id"`
	TagType           string   `json:"tag_type"`
	AssessmentVersion string   `json:"assessment_version"`
	Decision          string   `json:"decision"`
	Reason            string   `json:"reason"`
	EvidenceIDs       []string `json:"evidence_ids"`
	CreatedBy         string   `json:"created_by"`
	CreatedAt         string   `json:"created_at"`
}

type AccountAssessmentDetail struct {
	AccountID      string                      `json:"account_id"`
	State          string                      `json:"state"`
	AsOf           string                      `json:"as_of"`
	Tags           []AccountTagAssessment      `json:"tags"`
	History        []AccountTagAssessment      `json:"history"`
	HistoryHasMore bool                        `json:"history_has_more"`
	Endpoints      []AccountAssessmentEndpoint `json:"endpoints"`
	Reviews        []AccountTagReview          `json:"reviews"`
}

type AccountAssessmentQuery struct {
	Keyword       string
	Tags          []string
	EvidenceLevel string
	ReviewState   string
	State         string
	Limit         int
	Cursor        int
}

type AccountTagReviewRequest struct {
	TagType           string `json:"tag_type"`
	AssessmentVersion string `json:"assessment_version"`
	Decision          string `json:"decision"`
	Reason            string `json:"reason"`
	CreatedBy         string `json:"-"`
}

var ErrAccountAssessmentVersionChanged = errors.New("account tag assessment version changed")

type AccountAssessmentReader interface {
	ListAccountAssessments(context.Context, AccountAssessmentQuery) (AccountAssessmentPage, error)
	GetAccountAssessment(context.Context, string) (AccountAssessmentDetail, bool, error)
}

type AccountAssessmentWriter interface {
	CreateAccountTagReview(context.Context, string, AccountTagReviewRequest) (AccountTagReview, error)
}

func accountTagVersion(item AccountTagAssessment) string {
	raw, _ := json.Marshal([]any{item.AccountID, item.TagType, item.EvidenceLevel, item.SourceType, item.Reason, item.EndpointIDs, item.EvidenceIDs, item.RuleVersion})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func (s *PostgresStore) buildAccountTagAssessments(ctx context.Context, account string, now time.Time) ([]AccountTagAssessment, error) {
	items := map[string]AccountTagAssessment{}
	// Collapse the account's sessions to endpoints before the shared-endpoint check. The
	// anti-join used to run once per session: a shared account with 23,725 sessions on 5
	// MACs probed ~110M index tuples, timed out on every attempt and pinned the lane.
	rows, err := s.db.QueryContext(ctx, `WITH mine AS MATERIALIZED (
 SELECT endpoint_id,min(started_at) AS first_seen,max(COALESCE(ended_at,started_at)) AS last_seen
 FROM account_sessions
 WHERE account_id=$1 AND endpoint_id IS NOT NULL AND endpoint_id<>'' AND COALESCE(ended_at,started_at)>=$2
 GROUP BY endpoint_id)
SELECT p.endpoint_id,p.device_type,p.device_type_confidence,p.fingerprint_version,m.first_seen,m.last_seen
FROM mine m JOIN endpoint_device_profiles p ON p.endpoint_id=m.endpoint_id
WHERE NOT p.recognition_conflict
 AND NOT EXISTS (
   SELECT 1 FROM account_sessions conflicting
   WHERE conflicting.endpoint_id=m.endpoint_id
     AND conflicting.account_id<>$1
     AND conflicting.account_id<>''
     AND COALESCE(conflicting.ended_at,conflicting.started_at)>=$2
 )`, account, now.Add(-accountTagWindow))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var endpoint, deviceType, version string
		var score float64
		var first, last time.Time
		if err = rows.Scan(&endpoint, &deviceType, &score, &version, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		tag := ""
		switch strings.ToLower(deviceType) {
		case "mobile", "phone", "smartphone", "tablet":
			tag = "mobile"
		case "desktop", "pc", "laptop", "workstation":
			tag = "pc"
		}
		if tag == "" {
			continue
		}
		level := "likely"
		if score >= .9 {
			level = "confirmed"
		} else if score < .7 {
			level = "clue"
		}
		candidate := items[tag]
		if candidate.TagType == "" {
			candidate = AccountTagAssessment{AccountID: account, TagType: tag, State: "current", EvidenceLevel: level, SourceType: "endpoint_recognition", Reason: map[string]string{"mobile": "近 7 天认证关联终端识别为手机或平板", "pc": "近 7 天认证关联终端识别为 PC"}[tag], RuleVersion: version, RawScore: score, FirstSeen: first.UTC().Format(time.RFC3339Nano), LastSeen: last.UTC().Format(time.RFC3339Nano)}
		}
		candidate.EndpointIDs = append(candidate.EndpointIDs, endpoint)
		candidate.EvidenceIDs = append(candidate.EvidenceIDs, "endpoint:"+endpoint)
		if score > candidate.RawScore {
			candidate.RawScore = score
			candidate.EvidenceLevel = level
		}
		if last.Format(time.RFC3339Nano) > candidate.LastSeen {
			candidate.LastSeen = last.UTC().Format(time.RFC3339Nano)
		}
		candidate.ValidUntil = last.Add(accountTagWindow).UTC().Format(time.RFC3339Nano)
		items[tag] = candidate
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	bindingRows, err := s.db.QueryContext(ctx, `SELECT DISTINCT endpoint_id,regexp_replace(lower(COALESCE(mac,'')),'[^0-9a-f]','','g')
FROM account_sessions WHERE account_id=$1 AND COALESCE(ended_at,started_at)>=$2`, account, now.Add(-accountTagWindow))
	if err != nil {
		return nil, err
	}
	bindingEndpoints, bindingMACs := []string{}, []string{}
	for bindingRows.Next() {
		var endpoint, mac string
		if err = bindingRows.Scan(&endpoint, &mac); err != nil {
			bindingRows.Close()
			return nil, err
		}
		if endpoint != "" {
			bindingEndpoints = append(bindingEndpoints, endpoint)
		}
		if mac != "" {
			bindingMACs = append(bindingMACs, mac)
		}
	}
	if err = bindingRows.Err(); err != nil {
		bindingRows.Close()
		return nil, err
	}
	bindingRows.Close()
	routerRows, err := s.db.QueryContext(ctx, `SELECT assessment_id,status,confidence,rule_version,first_seen,last_seen,expires_at,COALESCE(endpoint_id,'') FROM (
 SELECT * FROM router_assessments WHERE endpoint_id=ANY($1)
 UNION ALL
 SELECT * FROM router_assessments WHERE mac<>'' AND regexp_replace(lower(mac),'[^0-9a-f]','','g')=ANY($2) AND NOT(endpoint_id=ANY($1))
) r WHERE r.expires_at>$3 AND r.status IN('confirmed','likely') AND NOT r.ambiguous`, bindingEndpoints, bindingMACs, now)
	if err != nil {
		return nil, err
	}
	for routerRows.Next() {
		var id, status, version, endpoint string
		var score int
		var first, last, expires time.Time
		if err = routerRows.Scan(&id, &status, &score, &version, &first, &last, &expires, &endpoint); err != nil {
			routerRows.Close()
			return nil, err
		}
		level := "likely"
		if status == "confirmed" {
			level = "confirmed"
		}
		candidate := items["router"]
		if candidate.TagType == "" {
			candidate = AccountTagAssessment{AccountID: account, TagType: "router", State: "current", EvidenceLevel: level, SourceType: "router_observation", Reason: "认证账号与路由设备存在精确终端或 MAC 绑定", RuleVersion: version, RawScore: float64(score), FirstSeen: first.UTC().Format(time.RFC3339Nano), LastSeen: last.UTC().Format(time.RFC3339Nano), ValidUntil: expires.UTC().Format(time.RFC3339Nano)}
		}
		candidate.EvidenceIDs = append(candidate.EvidenceIDs, id)
		if endpoint != "" {
			candidate.EndpointIDs = append(candidate.EndpointIDs, endpoint)
		}
		if score > int(candidate.RawScore) {
			candidate.RawScore = float64(score)
			candidate.EvidenceLevel = level
		}
		items["router"] = candidate
	}
	if err = routerRows.Err(); err != nil {
		routerRows.Close()
		return nil, err
	}
	routerRows.Close()

	var riskID, basis, level string
	var confidence float64
	var first, last time.Time
	var evidenceRaw []byte
	err = s.db.QueryRowContext(ctx, `SELECT subject_id,COALESCE(detection_basis,''),COALESCE(assessment_level,level),confidence,updated_at,updated_at,evidence_ids
		FROM subject_risk_snapshots WHERE account_id=$1 AND updated_at>=$2 AND COALESCE(assessment_level,level) NOT IN('normal','low') AND COALESCE(review_disposition,'') NOT IN('false_positive','benign')
		ORDER BY updated_at DESC LIMIT 1`, account, now.Add(-24*time.Hour)).Scan(&riskID, &basis, &level, &confidence, &first, &last, &evidenceRaw)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == nil {
		evidenceIDs := []string{}
		_ = json.Unmarshal(evidenceRaw, &evidenceIDs)
		if len(evidenceIDs) == 0 {
			evidenceIDs = []string{riskID}
		}
		evidenceLevel := "likely"
		if level == "confirmed" || level == "high" {
			evidenceLevel = "confirmed"
		}
		reason := "当前有效研判存在代理行为依据"
		if strings.Contains(basis, "shared") {
			reason = "当前有效研判存在共享上网依据"
		}
		items["proxy"] = AccountTagAssessment{AccountID: account, TagType: "proxy", State: "current", EvidenceLevel: evidenceLevel, SourceType: "risk_assessment", Reason: reason, EvidenceIDs: evidenceIDs, RawScore: confidence, FirstSeen: first.UTC().Format(time.RFC3339Nano), LastSeen: last.UTC().Format(time.RFC3339Nano), ValidUntil: last.Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)}
	}
	out := make([]AccountTagAssessment, 0, len(items))
	for _, item := range items {
		sort.Strings(item.EndpointIDs)
		sort.Strings(item.EvidenceIDs)
		item.AssessmentVersion = accountTagVersion(item)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TagType < out[j].TagType })
	return out, nil
}

func (s *PostgresStore) materializeAccountTags(ctx context.Context, account string, generation int64) error {
	items, err := s.buildAccountTagAssessments(ctx, account, time.Now().UTC())
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Tags are rebuildable from account_sessions; a lost commit leaves the job dirty and
	// re-claimable, so this derived write does not wait for a WAL fsync.
	if _, err = tx.ExecContext(ctx, `SET LOCAL synchronous_commit = off`); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, item := range items {
		seen[item.TagType] = true
		endpoints, _ := json.Marshal(item.EndpointIDs)
		evidence, _ := json.Marshal(item.EvidenceIDs)
		_, err = tx.ExecContext(ctx, `INSERT INTO account_tag_assessment_history(account_id,tag_type,assessment_version,state,evidence_level,source_type,reason,endpoint_ids,evidence_ids,rule_version,raw_score,first_seen,last_seen,valid_until)
SELECT account_id,tag_type,assessment_version,'historical',evidence_level,source_type,reason,endpoint_ids,evidence_ids,rule_version,raw_score,first_seen,last_seen,valid_until
FROM account_tag_assessments WHERE account_id=$1 AND tag_type=$2 AND assessment_version<>$3
AND (evidence_level,source_type,reason,endpoint_ids,evidence_ids,rule_version) IS DISTINCT FROM ($4,$5,$6,$7::jsonb,$8::jsonb,$9)
ON CONFLICT(account_id,tag_type,assessment_version) DO NOTHING`, account, item.TagType, item.AssessmentVersion, item.EvidenceLevel, item.SourceType, item.Reason, string(endpoints), string(evidence), item.RuleVersion)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO account_tag_assessments(account_id,tag_type,assessment_version,state,evidence_level,source_type,reason,endpoint_ids,evidence_ids,rule_version,raw_score,first_seen,last_seen,valid_until) VALUES($1,$2,$3,'current',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(account_id,tag_type) DO UPDATE SET assessment_version=CASE WHEN (account_tag_assessments.evidence_level,account_tag_assessments.source_type,account_tag_assessments.reason,account_tag_assessments.endpoint_ids,account_tag_assessments.evidence_ids,account_tag_assessments.rule_version) IS DISTINCT FROM (EXCLUDED.evidence_level,EXCLUDED.source_type,EXCLUDED.reason,EXCLUDED.endpoint_ids,EXCLUDED.evidence_ids,EXCLUDED.rule_version) THEN EXCLUDED.assessment_version ELSE account_tag_assessments.assessment_version END,state='current',evidence_level=EXCLUDED.evidence_level,source_type=EXCLUDED.source_type,reason=EXCLUDED.reason,endpoint_ids=EXCLUDED.endpoint_ids,evidence_ids=EXCLUDED.evidence_ids,rule_version=EXCLUDED.rule_version,raw_score=EXCLUDED.raw_score,first_seen=LEAST(account_tag_assessments.first_seen,EXCLUDED.first_seen),last_seen=EXCLUDED.last_seen,valid_until=EXCLUDED.valid_until,updated_at=now()`, account, item.TagType, item.AssessmentVersion, item.EvidenceLevel, item.SourceType, item.Reason, endpoints, evidence, item.RuleVersion, item.RawScore, item.FirstSeen, item.LastSeen, item.ValidUntil)
		if err != nil {
			return err
		}
	}
	for _, tag := range []string{"proxy", "router", "mobile", "pc"} {
		if seen[tag] {
			continue
		}
		_, err = tx.ExecContext(ctx, `UPDATE account_tag_assessments SET state='historical',updated_at=now() WHERE account_id=$1 AND tag_type=$2 AND state='current'`, account, tag)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE account_tag_projection_jobs SET processed_generation=GREATEST(processed_generation,$2),priority=CASE WHEN dirty_generation<=$2 THEN 0 ELSE priority END,lease_owner='',lease_until='-infinity',attempts=0,last_error='',updated_at=now() WHERE account_id=$1`, account, generation)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE account_tag_projection_runtime SET last_success_at=now(),last_error='',processed_jobs=processed_jobs+1,updated_at=now() WHERE singleton`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *DBStore) runAccountTagMaterializer(ctx context.Context) {
	worker := fmt.Sprintf("account-tags-%d", time.Now().UnixNano())
	for ctx.Err() == nil {
		var account string
		var generation int64
		var priority int
		err := s.pg.db.QueryRowContext(ctx, `UPDATE account_tag_projection_jobs SET lease_owner=$1,lease_until=now()+interval '20 seconds' WHERE account_id=(SELECT account_id FROM account_tag_projection_jobs WHERE dirty_generation>processed_generation AND not_before<=now() AND lease_until<now() ORDER BY priority DESC,updated_at,account_id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING account_id,dirty_generation,priority`, worker).Scan(&account, &generation, &priority)
		if err == nil {
			work, cancel := context.WithTimeout(ctx, 15*time.Second)
			runErr := s.pg.materializeAccountTags(work, account, generation)
			cancel()
			if runErr != nil {
				// Back off exponentially and move behind same-priority work. A fixed one-second
				// retry with an unchanged updated_at kept one failing account at the head of
				// the queue, occupying the lane about 15 of every 16 seconds.
				_, _ = s.pg.db.ExecContext(ctx, `UPDATE account_tag_projection_jobs SET attempts=attempts+1,lease_owner='',lease_until='-infinity',last_error=$2,not_before=now()+make_interval(secs=>least(300,power(2,least(attempts,9)))),updated_at=now() WHERE account_id=$1`, account, runErr.Error())
				_, _ = s.pg.db.ExecContext(ctx, `UPDATE account_tag_projection_runtime SET last_error=$1,updated_at=now() WHERE singleton`, runErr.Error())
			}
			if priority == 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
			continue
		}
		if err != sql.ErrNoRows && ctx.Err() == nil {
			_, _ = s.pg.db.ExecContext(ctx, `UPDATE account_tag_projection_runtime SET last_error=$1,updated_at=now() WHERE singleton`, err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func scanAccountTag(rows interface{ Scan(...any) error }) (AccountTagAssessment, error) {
	var item AccountTagAssessment
	var endpoints, evidence []byte
	var first, last, valid, recorded time.Time
	err := rows.Scan(&item.AccountID, &item.TagType, &item.AssessmentVersion, &item.State, &item.EvidenceLevel, &item.SourceType, &item.Reason, &endpoints, &evidence, &item.RuleVersion, &item.RawScore, &first, &last, &valid, &item.ReviewState, &recorded)
	if err != nil {
		return item, err
	}
	_ = json.Unmarshal(endpoints, &item.EndpointIDs)
	_ = json.Unmarshal(evidence, &item.EvidenceIDs)
	item.FirstSeen = first.UTC().Format(time.RFC3339Nano)
	item.LastSeen = last.UTC().Format(time.RFC3339Nano)
	item.ValidUntil = valid.UTC().Format(time.RFC3339Nano)
	item.RecordedAt = recorded.UTC().Format(time.RFC3339Nano)
	return item, nil
}

func (s *PostgresStore) ListAccountAssessments(ctx context.Context, q AccountAssessmentQuery) (AccountAssessmentPage, error) {
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 20
	}
	reviewExpr := `COALESCE((SELECT decision FROM account_tag_reviews r WHERE r.account_id=a.account_id AND r.tag_type=a.tag_type AND r.assessment_version=a.assessment_version ORDER BY created_at DESC LIMIT 1),'pending')`
	where := []string{"a.state='current'"}
	source := "account_tag_assessments a"
	args := []any{}
	if q.State == "historical" {
		where = []string{"a.state='historical'"}
		source = `(SELECT account_id,tag_type,assessment_version,state,evidence_level,source_type,reason,endpoint_ids,evidence_ids,rule_version,raw_score,first_seen,last_seen,valid_until
FROM account_tag_assessment_history
UNION ALL
SELECT account_id,tag_type,assessment_version,state,evidence_level,source_type,reason,endpoint_ids,evidence_ids,rule_version,raw_score,first_seen,last_seen,valid_until
FROM account_tag_assessments WHERE state='historical') a`
	}
	if q.Keyword != "" {
		args = append(args, "%"+strings.ToLower(q.Keyword)+"%")
		where = append(where, fmt.Sprintf("lower(a.account_id) LIKE $%d", len(args)))
	}
	if len(q.Tags) > 0 {
		args = append(args, q.Tags)
		where = append(where, fmt.Sprintf("a.tag_type=ANY($%d::text[])", len(args)))
	}
	if q.EvidenceLevel != "" {
		args = append(args, q.EvidenceLevel)
		where = append(where, fmt.Sprintf("a.evidence_level=$%d", len(args)))
	}
	if q.ReviewState != "" {
		args = append(args, q.ReviewState)
		where = append(where, fmt.Sprintf("%s=$%d", reviewExpr, len(args)))
	} else if q.State != "historical" {
		where = append(where, reviewExpr+"<>'reject'")
	}
	whereSQL := " WHERE " + strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(DISTINCT a.account_id) FROM `+source+whereSQL, args...).Scan(&total); err != nil {
		return AccountAssessmentPage{}, err
	}
	args = append(args, q.Limit, q.Cursor)
	filterArgs := append([]any{}, args[:len(args)-2]...)
	pageRows, pageErr := s.db.QueryContext(ctx, `SELECT a.account_id,max(a.last_seen) FROM `+source+whereSQL+` GROUP BY a.account_id ORDER BY max(a.last_seen) DESC,a.account_id LIMIT $`+fmt.Sprint(len(filterArgs)+1)+` OFFSET $`+fmt.Sprint(len(filterArgs)+2), append(filterArgs, q.Limit, q.Cursor)...)
	if pageErr != nil {
		return AccountAssessmentPage{}, pageErr
	}
	ids := []string{}
	for pageRows.Next() {
		var id string
		var ignored time.Time
		if pageErr = pageRows.Scan(&id, &ignored); pageErr != nil {
			pageRows.Close()
			return AccountAssessmentPage{}, pageErr
		}
		ids = append(ids, id)
	}
	pageRows.Close()
	if pageErr != nil {
		return AccountAssessmentPage{}, pageErr
	}
	tagReviewFilter := ""
	if q.State != "historical" && q.ReviewState != "reject" {
		tagReviewFilter = " AND " + reviewExpr + "<>'reject'"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.account_id,a.tag_type,a.assessment_version,a.state,a.evidence_level,a.source_type,a.reason,a.endpoint_ids,a.evidence_ids,a.rule_version,a.raw_score,a.first_seen,a.last_seen,a.valid_until,`+reviewExpr+`,a.last_seen FROM `+source+` WHERE a.account_id=ANY($1::text[]) AND a.state=$2`+tagReviewFilter+` ORDER BY array_position($1::text[],a.account_id),a.tag_type,a.last_seen DESC`, ids, func() string {
		if q.State == "historical" {
			return "historical"
		}
		return "current"
	}())
	if err != nil {
		return AccountAssessmentPage{}, err
	}
	defer rows.Close()
	by := map[string]*AccountAssessmentListItem{}
	endpointSets := map[string]map[string]bool{}
	order := []string{}
	for rows.Next() {
		item, e := scanAccountTag(rows)
		if e != nil {
			return AccountAssessmentPage{}, e
		}
		entry := by[item.AccountID]
		if entry == nil {
			entry = &AccountAssessmentListItem{AccountID: item.AccountID, ReviewState: "confirmed"}
			by[item.AccountID] = entry
			endpointSets[item.AccountID] = map[string]bool{}
			order = append(order, item.AccountID)
		}
		entry.Tags = append(entry.Tags, item)
		for _, endpointID := range item.EndpointIDs {
			endpointSets[item.AccountID][endpointID] = true
		}
		entry.EndpointCount = len(endpointSets[item.AccountID])
		if entry.PrimaryReason == "" {
			entry.PrimaryReason = item.Reason
		}
		if item.LastSeen > entry.LastAssessed {
			entry.LastAssessed = item.LastSeen
		}
		if item.ReviewState == "pending" {
			entry.ReviewState = "pending"
		} else if item.ReviewState == "reject" && entry.ReviewState != "pending" {
			entry.ReviewState = "reject"
		}
	}
	items := make([]AccountAssessmentListItem, 0, len(order))
	for _, id := range order {
		items = append(items, *by[id])
	}
	var asOf sql.NullTime
	var runtimeErr string
	_ = s.db.QueryRowContext(ctx, `SELECT last_success_at,last_error FROM account_tag_projection_runtime WHERE singleton`).Scan(&asOf, &runtimeErr)
	state := "processing"
	if runtimeErr != "" {
		state = "failed"
	} else if asOf.Valid {
		state = "ready"
		if time.Since(asOf.Time) > 15*time.Second {
			state = "stale"
		}
	}
	if total == 0 && state != "failed" && state != "processing" {
		state = "no_records"
	}
	asOfText := ""
	if asOf.Valid {
		asOfText = asOf.Time.UTC().Format(time.RFC3339Nano)
	}
	var next *string
	if q.Cursor+len(items) < total {
		v := fmt.Sprint(q.Cursor + len(items))
		next = &v
	}
	return AccountAssessmentPage{Items: items, State: state, AsOf: asOfText, Page: Page{Limit: q.Limit, NextCursor: next, Total: total}}, rows.Err()
}

func (s *PostgresStore) GetAccountAssessment(ctx context.Context, account string) (AccountAssessmentDetail, bool, error) {
	detail := AccountAssessmentDetail{AccountID: account, Tags: []AccountTagAssessment{}, History: []AccountTagAssessment{}, Endpoints: []AccountAssessmentEndpoint{}, Reviews: []AccountTagReview{}}
	rows, err := s.db.QueryContext(ctx, `SELECT a.account_id,a.tag_type,a.assessment_version,a.state,a.evidence_level,a.source_type,a.reason,a.endpoint_ids,a.evidence_ids,a.rule_version,a.raw_score,a.first_seen,a.last_seen,a.valid_until,COALESCE((SELECT decision FROM account_tag_reviews r WHERE r.account_id=a.account_id AND r.tag_type=a.tag_type AND r.assessment_version=a.assessment_version),'pending'),a.updated_at
FROM account_tag_assessments a WHERE a.account_id=$1 ORDER BY a.tag_type`, account)
	if err != nil {
		return detail, false, err
	}
	endpointSet := map[string]bool{}
	for rows.Next() {
		item, e := scanAccountTag(rows)
		if e != nil {
			rows.Close()
			return detail, false, e
		}
		if item.State == "current" && item.ReviewState != "reject" {
			detail.Tags = append(detail.Tags, item)
		} else {
			detail.History = append(detail.History, item)
		}
		for _, id := range item.EndpointIDs {
			endpointSet[id] = true
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return detail, false, err
	}
	rows.Close()
	// Historical versions are retained for audit. The detail page reads one latest
	// representative per distinct conclusion and omits conclusions still current.
	// A timestamp-only refresh must never fill the page or fetch thousands of rows.
	hrows, err := s.db.QueryContext(ctx, `WITH distinct_conclusions AS (
 SELECT DISTINCT ON (h.tag_type,h.evidence_level,h.source_type,h.reason,h.rule_version)
  h.account_id,h.tag_type,h.assessment_version,h.state,h.evidence_level,h.source_type,h.reason,h.endpoint_ids,h.evidence_ids,h.rule_version,h.raw_score,h.first_seen,h.last_seen,h.valid_until,h.recorded_at,h.history_id
 FROM account_tag_assessment_history h WHERE h.account_id=$1
 ORDER BY h.tag_type,h.evidence_level,h.source_type,h.reason,h.rule_version,h.recorded_at DESC,h.history_id DESC
)
SELECT h.account_id,h.tag_type,h.assessment_version,'historical',h.evidence_level,h.source_type,h.reason,h.endpoint_ids,h.evidence_ids,h.rule_version,h.raw_score,h.first_seen,h.last_seen,h.valid_until,COALESCE((SELECT decision FROM account_tag_reviews r WHERE r.account_id=h.account_id AND r.tag_type=h.tag_type AND r.assessment_version=h.assessment_version),'pending'),h.recorded_at
FROM distinct_conclusions h
WHERE NOT EXISTS (SELECT 1 FROM account_tag_assessments a WHERE a.account_id=h.account_id AND a.tag_type=h.tag_type AND a.evidence_level=h.evidence_level AND a.source_type=h.source_type AND a.reason=h.reason AND a.rule_version=h.rule_version)
ORDER BY h.recorded_at DESC,h.history_id DESC LIMIT 51`, account)
	if err != nil {
		return detail, false, err
	}
	historyCount := 0
	for hrows.Next() {
		item, e := scanAccountTag(hrows)
		if e != nil {
			hrows.Close()
			return detail, false, e
		}
		if historyCount == 50 {
			detail.HistoryHasMore = true
			break
		}
		detail.History = append(detail.History, item)
		historyCount++
		for _, id := range item.EndpointIDs {
			endpointSet[id] = true
		}
	}
	if err = hrows.Err(); err != nil {
		hrows.Close()
		return detail, false, err
	}
	hrows.Close()
	if len(detail.Tags)+len(detail.History) == 0 {
		return detail, false, nil
	}
	ids := make([]string, 0, len(endpointSet))
	for id := range endpointSet {
		ids = append(ids, id)
	}
	if len(ids) > 0 {
		erows, e := s.db.QueryContext(ctx, `SELECT e.endpoint_id,COALESCE(e.primary_mac,''),COALESCE(p.brand,''),COALESCE(p.model,''),COALESCE(p.device_type,''),e.last_seen,CASE WHEN COALESCE(p.device_type_confidence,0)>=.9 THEN 'confirmed' WHEN COALESCE(p.device_type_confidence,0)>=.7 THEN 'likely' ELSE 'clue' END FROM endpoint_entities e LEFT JOIN endpoint_device_profiles p USING(endpoint_id) WHERE e.endpoint_id=ANY($1::text[]) ORDER BY e.last_seen DESC`, ids)
		if e != nil {
			return detail, false, e
		}
		for erows.Next() {
			var item AccountAssessmentEndpoint
			var last sql.NullTime
			if e = erows.Scan(&item.EndpointID, &item.PrimaryMAC, &item.Brand, &item.Model, &item.DeviceType, &last, &item.EvidenceLevel); e != nil {
				erows.Close()
				return detail, false, e
			}
			if last.Valid {
				item.LastSeen = last.Time.UTC().Format(time.RFC3339Nano)
			}
			detail.Endpoints = append(detail.Endpoints, item)
		}
		erows.Close()
	}
	rrows, e := s.db.QueryContext(ctx, `SELECT review_id,account_id,tag_type,assessment_version,decision,reason,evidence_ids,created_by,created_at FROM account_tag_reviews WHERE account_id=$1 ORDER BY created_at DESC`, account)
	if e != nil {
		return detail, false, e
	}
	for rrows.Next() {
		var item AccountTagReview
		var raw []byte
		var at time.Time
		if e = rrows.Scan(&item.ReviewID, &item.AccountID, &item.TagType, &item.AssessmentVersion, &item.Decision, &item.Reason, &raw, &item.CreatedBy, &at); e != nil {
			rrows.Close()
			return detail, false, e
		}
		_ = json.Unmarshal(raw, &item.EvidenceIDs)
		item.CreatedAt = at.UTC().Format(time.RFC3339Nano)
		detail.Reviews = append(detail.Reviews, item)
	}
	rrows.Close()
	var at sql.NullTime
	var runtimeErr string
	_ = s.db.QueryRowContext(ctx, `SELECT last_success_at,last_error FROM account_tag_projection_runtime WHERE singleton`).Scan(&at, &runtimeErr)
	detail.State = "processing"
	if runtimeErr != "" {
		detail.State = "failed"
	} else if at.Valid {
		detail.State = "ready"
		detail.AsOf = at.Time.UTC().Format(time.RFC3339Nano)
	}
	return detail, true, nil
}

func (s *PostgresStore) CreateAccountTagReview(ctx context.Context, account string, request AccountTagReviewRequest) (AccountTagReview, error) {
	var current string
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT assessment_version,evidence_ids FROM account_tag_assessments WHERE account_id=$1 AND tag_type=$2 AND state='current'`, account, request.TagType).Scan(&current, &raw)
	if err != nil {
		return AccountTagReview{}, err
	}
	if current != request.AssessmentVersion {
		return AccountTagReview{}, ErrAccountAssessmentVersionChanged
	}
	sum := sha256.Sum256([]byte(account + request.TagType + current + request.Decision + time.Now().UTC().String()))
	review := AccountTagReview{ReviewID: fmt.Sprintf("tag-review-%x", sum[:8]), AccountID: account, TagType: request.TagType, AssessmentVersion: current, Decision: request.Decision, Reason: strings.TrimSpace(request.Reason), CreatedBy: request.CreatedBy, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	_ = json.Unmarshal(raw, &review.EvidenceIDs)
	_, err = s.db.ExecContext(ctx, `INSERT INTO account_tag_reviews(review_id,account_id,tag_type,assessment_version,decision,reason,evidence_ids,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(account_id,tag_type,assessment_version) DO UPDATE SET decision=EXCLUDED.decision,reason=EXCLUDED.reason,evidence_ids=EXCLUDED.evidence_ids,created_by=EXCLUDED.created_by,created_at=EXCLUDED.created_at`, review.ReviewID, account, request.TagType, current, request.Decision, review.Reason, raw, review.CreatedBy, review.CreatedAt)
	return review, err
}
