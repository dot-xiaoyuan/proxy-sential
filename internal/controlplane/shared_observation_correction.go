package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"strings"
	"time"
)

type SharedObservationCorrectionBatch struct {
	RunID           string    `json:"run_id"`
	Inspected       int       `json:"inspected"`
	Insufficient    int       `json:"insufficient_evidence"`
	Unverified      int       `json:"unverified"`
	NextEvaluatedAt time.Time `json:"next_evaluated_at"`
	NextDecisionID  string    `json:"next_decision_id"`
	Completed       bool      `json:"completed"`
}

type sharedCorrectionCandidate struct {
	id          string
	evaluatedAt time.Time
	version     string
	document    []byte
}

// Only the saved decision's own evidence can establish a historical defect.
// Missing or unreadable evidence is a separate, explicitly unfinished review.
func classifyHistoricalSharedDecision(raw []byte) (classification, reason string) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || len(envelope["evidence"]) == 0 || string(envelope["evidence"]) == "null" {
		return "unverified", "saved_evidence_unavailable"
	}
	var d sharedaccess.ObservationDecision
	if json.Unmarshal(raw, &d) != nil || d.Result != "matched" {
		return "unverified", "saved_decision_unreadable_or_mismatched"
	}
	if d.Evidence.ID == "" || len(d.Evidence.EventIDs) == 0 {
		return "unverified", "saved_evidence_unavailable"
	}
	if d.Evidence.StrongAnchor == "" {
		return "insufficient_evidence", "strong_anchor_missing"
	}
	if d.Evidence.DeviceLowerBound < 2 {
		return "insufficient_evidence", "device_lower_bound_below_two"
	}
	if !d.Evidence.Complete || !d.Evidence.CoverageVerified || len(d.Evidence.Conflicts) > 0 {
		return "insufficient_evidence", "coverage_or_conflict_not_verified"
	}
	return "", ""
}

// ReviewHistoricalSharedDecisionBatch examines at most limit saved decisions.
// The run's immutable cutoffs and decision-time cursor make interruption and retry visible;
// this function never recomputes evidence from current device or identity state.
func ReviewHistoricalSharedDecisionBatch(ctx context.Context, db *sql.DB, runID string, badRuleBefore, receivedBefore time.Time, limit int) (SharedObservationCorrectionBatch, error) {
	var result SharedObservationCorrectionBatch
	if db == nil || strings.TrimSpace(runID) == "" || badRuleBefore.IsZero() || receivedBefore.IsZero() || limit < 1 || limit > 200 {
		return result, fmt.Errorf("correction batch requires a run ID, fixed cutoffs and a 1..200 limit")
	}
	result.RunID = runID
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='10s'`); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='2s'`); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_correction_runs(run_id,bad_rule_before,received_before)
 VALUES($1,$2,$3) ON CONFLICT(run_id) DO NOTHING`, runID, badRuleBefore, receivedBefore); err != nil {
		return result, err
	}
	var actualBad, actualReceived, cursorAt time.Time
	var cursorID, status string
	if err = tx.QueryRowContext(ctx, `SELECT bad_rule_before,received_before,cursor_evaluated_at,cursor_decision_id,status
 FROM shared_observation_correction_runs WHERE run_id=$1 FOR UPDATE`, runID).
		Scan(&actualBad, &actualReceived, &cursorAt, &cursorID, &status); err != nil {
		return result, err
	}
	if !actualBad.Equal(badRuleBefore) || !actualReceived.Equal(receivedBefore) {
		return result, fmt.Errorf("correction run %s has different immutable cutoffs", runID)
	}
	if status == "completed" {
		result.Completed = true
		result.NextEvaluatedAt = cursorAt
		result.NextDecisionID = cursorID
		return result, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT decision_id,evaluated_at,evidence_version,document
 FROM policy_decision_records WHERE trigger_type='shared_access' AND result='matched'
	AND evaluated_at<$1 AND first_received_at<=$2
	AND (evaluated_at,decision_id)>($3,$4)
	ORDER BY evaluated_at,decision_id LIMIT $5`, badRuleBefore, receivedBefore, cursorAt, cursorID, limit)
	if err != nil {
		return result, err
	}
	candidates := make([]sharedCorrectionCandidate, 0, limit)
	for rows.Next() {
		var candidate sharedCorrectionCandidate
		if err = rows.Scan(&candidate.id, &candidate.evaluatedAt, &candidate.version, &candidate.document); err != nil {
			rows.Close()
			return result, err
		}
		candidates = append(candidates, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	for _, candidate := range candidates {
		classification, reason := classifyHistoricalSharedDecision(candidate.document)
		if classification != "" {
			hash := sha256.Sum256(candidate.document)
			fingerprint := hex.EncodeToString(hash[:])
			var existingHash, existingClass, existingReason string
			err = tx.QueryRowContext(ctx, `INSERT INTO shared_observation_decision_corrections(decision_id,run_id,evidence_version,source_sha256,classification,reason)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(decision_id) DO NOTHING RETURNING source_sha256,classification,reason`,
				candidate.id, runID, candidate.version, fingerprint, classification, reason).Scan(&existingHash, &existingClass, &existingReason)
			if errors.Is(err, sql.ErrNoRows) {
				err = tx.QueryRowContext(ctx, `SELECT source_sha256,classification,reason FROM shared_observation_decision_corrections WHERE decision_id=$1`, candidate.id).
					Scan(&existingHash, &existingClass, &existingReason)
			}
			if err != nil || existingHash != fingerprint || existingClass != classification || existingReason != reason {
				return result, fmt.Errorf("historical correction conflict for decision %s: %w", candidate.id, errors.Join(err, fmt.Errorf("saved evidence differs")))
			}
			if classification == "insufficient_evidence" {
				result.Insufficient++
			} else {
				result.Unverified++
			}
		}
		result.Inspected++
		result.NextEvaluatedAt, result.NextDecisionID = candidate.evaluatedAt, candidate.id
	}
	result.Completed = len(candidates) < limit
	if result.Inspected == 0 {
		result.NextEvaluatedAt, result.NextDecisionID = cursorAt, cursorID
	}
	_, err = tx.ExecContext(ctx, `UPDATE shared_observation_correction_runs SET
	 cursor_evaluated_at=$2,cursor_decision_id=$3,inspected=inspected+$4,insufficient=insufficient+$5,
 unverified=unverified+$6,status=$7,updated_at=now() WHERE run_id=$1`,
		runID, result.NextEvaluatedAt, result.NextDecisionID, result.Inspected, result.Insufficient, result.Unverified,
		map[bool]string{true: "completed", false: "running"}[result.Completed])
	if err != nil {
		return result, err
	}
	auditID := "shared-correction-batch-" + policy.StableID(runID, cursorAt.UTC().Format(time.RFC3339Nano), cursorID,
		result.NextEvaluatedAt.UTC().Format(time.RFC3339Nano), result.NextDecisionID)
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome)
 VALUES($1,'system:shared-correction','shared_observation.historical_correction_batch',$2,$3)
 ON CONFLICT(audit_id) DO NOTHING`, auditID, runID,
		fmt.Sprintf("checked=%d insufficient=%d unverified=%d completed=%t", result.Inspected, result.Insufficient, result.Unverified, result.Completed))
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}
