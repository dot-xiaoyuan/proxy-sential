package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"strconv"
	"time"
)

// The scope deliberately excludes evidence version: a new observation of the
// same strong, continuously valid behavior extends the existing episode.
func sharedObservationEpisodeScope(d sharedaccess.ObservationDecision) string {
	return policy.StableID("shared-observation-episode-v1", d.PolicyID, strconv.Itoa(d.PolicyRevision),
		d.AccountID, d.Evidence.SensorID, d.CampusID, d.AccessDomain, d.IP, d.SessionGeneration)
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
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope); err != nil {
		return false, fmt.Errorf("lock shared observation episode: %w", err)
	}
	var executionID string
	err := tx.QueryRowContext(ctx, `SELECT e.execution_id FROM shared_observation_episode_index i
 JOIN shared_observation_executions e ON e.execution_id=i.execution_id
 WHERE i.episode_scope_key=$1 AND e.state='recorded' AND e.expires_at>$2
 ORDER BY e.expires_at DESC,e.execution_id DESC LIMIT 1 FOR UPDATE OF e`, scope, d.EvaluatedAt).Scan(&executionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("read shared observation episode: %w", err)
	}
	if err == nil {
		d.ExecutionID = executionID
		_, err = tx.ExecContext(ctx, `UPDATE shared_observation_executions SET
 evidence_version=$2,expires_at=GREATEST(expires_at,$3),
 document=jsonb_set(jsonb_set(jsonb_set(document,'{last_evaluated}',to_jsonb($4::timestamptz),true),
 '{evidence_ids}',jsonb_build_array($5::text),true),'{cooldown_until}',to_jsonb($3::timestamptz),true)
 WHERE execution_id=$1 AND state='recorded'`, executionID, d.EvidenceVersion, d.EvidenceExpiresAt, d.EvaluatedAt, d.ObservationID)
		return false, err
	}
	// A later episode can start with the same decision/evidence ID after an
	// explicit session end. Include the last durable episode in the new ID so
	// retries are stable while consecutive episodes remain distinct.
	var predecessor string
	err = tx.QueryRowContext(ctx, `SELECT e.execution_id FROM shared_observation_episode_index i
 JOIN shared_observation_executions e ON e.execution_id=i.execution_id
 WHERE i.episode_scope_key=$1 ORDER BY e.first_received_at DESC,e.execution_id DESC LIMIT 1`, scope).Scan(&predecessor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("read preceding shared observation episode: %w", err)
	}
	d.ExecutionID = "shared-observe-episode-" + policy.StableID(scope, d.DecisionID, predecessor)
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
	raw, err := json.Marshal(execution)
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
