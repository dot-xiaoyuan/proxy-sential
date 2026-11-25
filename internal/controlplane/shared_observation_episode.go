package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"strconv"
	"time"
)

// The scope deliberately excludes evidence version: a new observation of the
// same strong, continuously valid behavior extends the existing episode.
func sharedObservationEpisodeScope(d sharedaccess.ObservationDecision) string {
	return policy.StableID("shared-observation-episode-v1", d.PolicyID, strconv.Itoa(d.PolicyRevision),
		d.AccountID, d.Evidence.SensorID, d.CampusID, d.AccessDomain, d.IP, d.SessionGeneration)
}

func sharedSessionCaseKey(sensor, campus, domain, account, ip, generation string) string {
	return "shared-session:" + policy.StableID(sensor, campus, domain, account, ip, generation)
}

type sharedEpisodeSessionRef struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	StartedAt time.Time `json:"started_at"`
}

func sharedObservationEpisodeSessions(sessions []policy.Session, at time.Time) []sharedEpisodeSessionRef {
	result := []sharedEpisodeSessionRef{}
	for _, session := range sessions {
		if session.ID != "" && session.State(at) == "active" {
			result = append(result, sharedEpisodeSessionRef{ID: session.ID, Source: session.Source, StartedAt: session.StartedAt})
		}
	}
	return result
}

func sharedObservationEpisodeSessionsEnded(previous []sharedEpisodeSessionRef, current []policy.Session, at time.Time) bool {
	for _, old := range previous {
		for _, session := range current {
			if old.ID == session.ID && old.Source == session.Source && old.StartedAt.Equal(session.StartedAt) &&
				!session.EndedAt.IsZero() && !at.Before(session.EndedAt) {
				return true
			}
		}
	}
	return false
}

func closeSharedObservationEpisode(ctx context.Context, tx *sql.Tx, scope string, at time.Time) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope); err != nil {
		return fmt.Errorf("lock shared observation episode closure: %w", err)
	}
	_, err := tx.ExecContext(ctx, `UPDATE shared_observation_executions e SET state='expired',expires_at=LEAST(e.expires_at,$2),
 document=jsonb_set(e.document,'{state}','"expired"') FROM shared_observation_episode_index i
 WHERE i.episode_scope_key=$1 AND i.execution_id=e.execution_id AND e.state='recorded'`, scope, at)
	return err
}

// The caller's transaction also persists the decision, action, report and job
// ACK. The advisory lock serializes competing jobs for one account/session
// scope; the active-row lookup alone would allow two first actions.
func ensureSharedObservationEpisode(ctx context.Context, tx *sql.Tx, d *sharedaccess.ObservationDecision) (bool, error) {
	if d.Result != "matched" {
		return false, nil
	}
	if d.AccountID == "" || d.SessionGeneration == "" || d.EvidenceExpiresAt.IsZero() || !d.EvidenceExpiresAt.After(d.EvaluatedAt) {
		return false, fmt.Errorf("matched shared decision lacks an accountable live session or evidence expiry")
	}
	scope := sharedObservationEpisodeScope(*d)
	caseKey := sharedSessionCaseKey(d.Evidence.SensorID, d.CampusID, d.AccessDomain, d.AccountID, d.IP, d.SessionGeneration)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0)),pg_advisory_xact_lock(hashtextextended($2,0))`, scope, caseKey); err != nil {
		return false, fmt.Errorf("lock shared observation episode: %w", err)
	}
	// A retried decision belongs to its originally recorded case, including
	// when an operator has since closed it.
	err := tx.QueryRowContext(ctx, `SELECT execution_id,coalesce(nullif(f.case_id,''),nullif(d.document->>'case_id',''),'shared-'||execution_id)
 FROM policy_decision_records d LEFT JOIN shared_access_findings f ON f.observation_id=d.observation_id WHERE d.decision_id=$1 AND d.result='matched'`, d.DecisionID).Scan(&d.ExecutionID, &d.CaseID)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("read recorded sharing decision: %w", err)
	}
	var predecessor string
	var fresh, closed bool
	err = tx.QueryRowContext(ctx, `SELECT e.execution_id,coalesce(nullif(e.document->>'case_id',''),'shared-'||e.execution_id),
 e.state='recorded' AND e.expires_at>$2,coalesce(c.status IN ('closed','resolved'),false)
 FROM shared_observation_episode_index i JOIN shared_observation_executions e USING(execution_id)
 LEFT JOIN risk_cases c ON c.case_id=coalesce(nullif(e.document->>'case_id',''),'shared-'||e.execution_id)
 WHERE i.episode_scope_key=$1 ORDER BY e.first_received_at DESC,e.execution_id DESC LIMIT 1 FOR UPDATE OF e`, scope, d.EvaluatedAt).Scan(&predecessor, &d.CaseID, &fresh, &closed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("read preceding shared observation episode: %w", err)
	}
	if fresh && !closed {
		d.ExecutionID = predecessor
		_, err = tx.ExecContext(ctx, `UPDATE shared_observation_executions SET
 evidence_version=$2,expires_at=GREATEST(expires_at,$3),
 document=jsonb_set(jsonb_set(jsonb_set(document,'{last_evaluated}',to_jsonb($4::timestamptz),true),
 '{evidence_ids}',jsonb_build_array($5::text),true),'{cooldown_until}',to_jsonb($3::timestamptz),true)
 WHERE execution_id=$1 AND state='recorded'`, d.ExecutionID, d.EvidenceVersion, d.EvidenceExpiresAt, d.EvaluatedAt, d.ObservationID)
		return false, err
	}
	// A later episode can start with the same decision/evidence ID after an
	// explicit session end. Include the last durable episode in the new ID so
	// retries are stable while consecutive episodes remain distinct.
	d.ExecutionID = "shared-observe-episode-" + policy.StableID(scope, d.DecisionID, predecessor)
	if predecessor == "" || closed {
		// Executions age out of hot storage. The open investigation remains
		// addressable by the existing partial unique case index.
		err = tx.QueryRowContext(ctx, `SELECT case_id FROM risk_cases WHERE dedupe_key=$1 AND status<>'closed' AND status<>'resolved'`, caseKey).Scan(&d.CaseID)
		if errors.Is(err, sql.ErrNoRows) {
			d.CaseID = "shared-" + d.ExecutionID
		} else if err != nil {
			return false, err
		}
	}
	p := sharedaccess.ObservationPolicy()
	p.CooldownSeconds = d.CooldownSeconds
	actionIDs := []string{}
	if violationObservationOnly() {
		actionIDs = append(actionIDs, "shared-record:"+d.ExecutionID)
	}
	execution := policy.Execution{ID: d.ExecutionID, PolicyID: d.PolicyID, AccountID: d.AccountID,
		State: "recorded", Episode: 1, Episodes: []time.Time{d.EvaluatedAt}, StartedAt: d.EvaluatedAt,
		LastEvaluated: d.EvaluatedAt, CooldownUntil: d.EvidenceExpiresAt,
		EvidenceIDs: []string{d.ObservationID}, Definition: p,
		Stages: []policy.StageState{{Status: "recorded", ActionIDs: actionIDs, ExecuteCount: 0}}}
	raw, err := json.Marshal(struct {
		policy.Execution
		CaseID string `json:"case_id"`
	}{execution, d.CaseID})
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_executions(execution_id,account_id,evidence_version,state,document,expires_at)
 VALUES($1,$2,$3,'recorded',$4,$5) ON CONFLICT(execution_id) DO NOTHING`, d.ExecutionID, d.AccountID, d.EvidenceVersion, raw, d.EvidenceExpiresAt)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_episode_index(episode_scope_key,execution_id)
 VALUES($1,$2) ON CONFLICT(execution_id) DO NOTHING`, scope, d.ExecutionID)
	return err == nil, err
}

// Keep the compact session coordinates with the protected case snapshot so
// retiring hot decisions and executions does not retire the open case.
func retainSharedCaseSession(ctx context.Context, tx *sql.Tx, proof *store.SharedAccessCaseEvidence) error {
	var refs []byte
	err := tx.QueryRowContext(ctx, `SELECT document->>'evidence_expires_at', `+sharedCaseSessionRefsSQL+
		` FROM policy_decision_records d WHERE d.decision_id=$1 AND d.result='matched'`, proof.DecisionID).Scan(&proof.EvidenceExpiresAt, &refs)
	if err == nil {
		proof.SessionRefs = refs
	}
	return err
}

const sharedCaseSessionRefsSQL = `coalesce((
 SELECT jsonb_agg(jsonb_build_object('source',s.source,'sensor',s.sensor_id,'campus',s.campus_id,'domain',s.access_domain,
 'id',s.session_id,'observed_at',packet.at,'period',coalesce(nullif(s.heartbeat_interval_seconds,0),s.reconcile_interval_seconds)))
 FROM jsonb_to_recordset(d.document->'identity_evidence') AS s(source text,sensor_id text,campus_id text,access_domain text,session_id text,
 account_id text,ip text,started_at timestamptz,ended_at timestamptz,heartbeat_interval_seconds int,reconcile_interval_seconds int)
 CROSS JOIN LATERAL (SELECT CASE WHEN d.document->'attribution'->>'confirmation_basis'='authenticated_router'
 THEN (d.document#>>'{evidence,outlet_activity,at}')::timestamptz ELSE (d.document#>>'{evidence,to}')::timestamptz END AS at) packet
 WHERE s.account_id=d.account_id AND s.ip=host(d.subject_ip) AND s.started_at<=packet.at AND (s.ended_at='0001-01-01T00:00:00Z'::timestamptz OR s.ended_at IS NULL OR s.ended_at>packet.at)),'[]'::jsonb)`

// A mirror gap ends the action episode. An open investigation can survive
// the gap only while its saved binding still exists in the current projection.
func liveSharedCases(ctx context.Context, tx *sql.Tx, cases map[string]RiskCase, present map[string]bool) (map[string]bool, error) {
	live := map[string]bool{}
	if tx == nil {
		return live, nil
	}
	type lookup struct {
		Case     string          `json:"case_id"`
		Decision string          `json:"decision"`
		Account  string          `json:"account"`
		IP       string          `json:"ip"`
		Refs     json.RawMessage `json:"refs,omitempty"`
	}
	var batch []lookup
	size := 0
	flush := func() error {
		raw, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT k.case_id FROM jsonb_to_recordset($1::jsonb) k(case_id text,decision text,account text,ip text,refs jsonb)
 CROSS JOIN LATERAL jsonb_to_recordset(coalesce(k.refs,(SELECT `+sharedCaseSessionRefsSQL+` FROM policy_decision_records d WHERE d.decision_id=k.decision AND d.result='matched'))) s(source text,sensor text,campus text,domain text,id text,observed_at timestamptz,period int)
 LEFT JOIN account_identity_session_projection p ON (p.source,p.sensor_id,p.campus_id,p.access_domain,p.session_id,p.ip)=(s.source,s.sensor,s.campus,s.domain,s.id,k.ip)
 LEFT JOIN account_identity_projection_sources src ON (src.source,src.sensor_id,src.campus_id,src.access_domain)=(p.source,p.sensor_id,p.campus_id,p.access_domain)
 GROUP BY k.case_id HAVING bool_and(coalesce(p.account_id=k.account AND coalesce(p.document->>'ended_at','')=''
 AND coalesce((p.document->>'first_confirmed_at')::timestamptz,p.confirmed_at)<=s.observed_at AND s.period BETWEEN 1 AND 86400
 AND greatest(src.observed_at,p.confirmed_at)+make_interval(secs=>3*least(86400,s.period))>now(),false))`, raw)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				return err
			}
			live[id] = true
		}
		batch = batch[:0]
		size = 0
		return rows.Err()
	}
	for id, c := range cases {
		proof := c.EvidenceSnapshot.SharedAccess
		if present[id] || c.Status == "closed" || c.Status == "resolved" || proof == nil || proof.SessionGeneration == "" {
			continue
		}
		batch = append(batch, lookup{id, proof.DecisionID, c.AccountID, c.IP, proof.SessionRefs})
		size += len(proof.SessionRefs) + len(id) + len(proof.DecisionID) + len(c.AccountID) + len(c.IP) + 80
		if len(batch) == 64 || size >= 256<<10 {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if len(batch) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return live, nil
}
