package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// Observation mode is a release invariant for the three violation-workflow
// versions. It intentionally has no environment or API switch. The private
// override exists only so legacy transport tests can exercise receipt logic.
var legacyTransportTestBypass atomic.Bool

func violationObservationOnly() bool { return !legacyTransportTestBypass.Load() }

func (s *Server) recordOutboundObservation(ctx context.Context, key, kind, target string, facts any) {
	if s.operations == nil || s.operations.db == nil {
		return
	}
	payload, _ := json.Marshal(facts)
	var meta struct {
		CaseID string `json:"case_id"`
	}
	_ = json.Unmarshal(payload, &meta)
	_, err := s.operations.db.ExecContext(ctx, `INSERT INTO violation_observations(observation_key,kind,target,case_id,facts,observed_at)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(observation_key) DO NOTHING`, key, kind, target, meta.CaseID, payload, time.Now().UTC())
	if err != nil {
		s.operations.setHealthError(err)
	}
}

func (s *Server) blockOutboundAction(id string, revoke bool) {
	if s.operations == nil || id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.operations.db != nil && !s.operations.readView {
		tx, err := s.operations.db.BeginTx(ctx, nil)
		if err != nil {
			s.operations.setHealthError(err)
			return
		}
		defer tx.Rollback()
		var target, actionType, evidenceVersion, caseID, executionID string
		var evidenceIDs []byte
		err = tx.QueryRowContext(ctx, `UPDATE enforcement_actions SET status='blocked',last_error='观察模式：未执行外部动作',updated_at=now()
			WHERE action_id=$1 AND status IN ('pending','running')
			RETURNING COALESCE(account_id,''),action_type,COALESCE(ruleset_version,''),COALESCE(case_id,''),COALESCE(policy_parameters->>'execution_id',''),evidence_ids`, id).Scan(&target, &actionType, &evidenceVersion, &caseID, &executionID, &evidenceIDs)
		if err != nil {
			return
		}
		payload, _ := json.Marshal(map[string]any{"action_id": id, "revoke": revoke, "case_id": caseID, "policy_execution_id": executionID, "evidence_ids": json.RawMessage(evidenceIDs), "evidence_version": evidenceVersion, "reason": "observation_only"})
		_, err = tx.ExecContext(ctx, `INSERT INTO violation_observations(observation_key,kind,target,case_id,facts)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT(observation_key) DO NOTHING`, "action:"+id, "拟"+actionType, target, caseID, payload)
		if err != nil {
			s.operations.setHealthError(err)
			return
		}
		if err = tx.Commit(); err != nil {
			s.operations.setHealthError(err)
		}
		return
	}
	s.operations.mu.Lock()
	action, ok := s.operations.doc.Actions[id]
	observed := ok && (action.Status == "pending" || action.Status == "running")
	if observed {
		action.Status = "blocked"
		action.LastError = "观察模式：未执行外部动作"
		action.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		s.operations.doc.Actions[id] = action
		_ = s.operations.saveLocked()
	}
	s.operations.mu.Unlock()
	if observed {
		s.recordOutboundObservation(ctx, "action:"+id, "拟"+action.ActionType, action.AccountID, map[string]any{"action_id": id, "revoke": revoke, "case_id": action.CaseID, "policy_execution_id": action.PolicyParameters.ExecutionID, "evidence_ids": action.EvidenceIDs, "evidence_version": action.RulesetVersion, "reason": "observation_only"})
	}
}

func (s *Server) observeTestRequest(w http.ResponseWriter, r *http.Request, kind, target string) bool {
	if !violationObservationOnly() {
		return false
	}
	key := "test:" + kind + ":" + shortToken(10)
	s.recordOutboundObservation(r.Context(), key, kind, target, map[string]string{"reason": "observation_only"})
	writeJSON(w, http.StatusOK, map[string]any{"status": "拟测试", "observation_key": key, "external_request_sent": false})
	return true
}

func (s *Server) observeQueuedNotifications() {
	if s.operations == nil || s.operations.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.operations.db.ExecContext(ctx, `WITH moved AS (
		UPDATE notification_outbox SET status='cancelled',updated_at=now()
		WHERE notification_id IN (SELECT notification_id FROM notification_outbox WHERE status='queued' ORDER BY created_at LIMIT 100)
		RETURNING notification_id,account_id)
		INSERT INTO violation_observations(observation_key,kind,target,facts)
		SELECT 'notification:'||notification_id,'拟提醒',account_id,jsonb_build_object('notification_id',notification_id,'reason','observation_only') FROM moved WHERE true
		ON CONFLICT(observation_key) DO NOTHING`)
	if err != nil {
		s.operations.setHealthError(err)
	}
}

func (s *Server) observeQueuedBehaviorReports() {
	if s.operations == nil || s.operations.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.operations.db.ExecContext(ctx, `WITH moved AS (
		UPDATE behavior_report_outbox SET status='cancelled',updated_at=now()
		WHERE report_id IN (SELECT report_id FROM behavior_report_outbox WHERE status IN ('queued','sending') ORDER BY created_at LIMIT 100)
		RETURNING report_id,account_id)
		INSERT INTO violation_observations(observation_key,kind,target,facts)
		SELECT 'behavior-report:'||report_id,'拟行为上报',account_id,jsonb_build_object('report_id',report_id,'reason','observation_only') FROM moved WHERE true
		ON CONFLICT(observation_key) DO NOTHING`)
	if err != nil {
		s.operations.setHealthError(err)
	}
}
