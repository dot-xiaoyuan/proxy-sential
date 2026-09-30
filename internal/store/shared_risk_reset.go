package store

import (
	"context"
	"database/sql"
	"fmt"
)

type SharedRiskResetReport struct {
	RiskSnapshots          int64 `json:"risk_snapshots"`
	Cases                  int64 `json:"cases"`
	CaseTimeline           int64 `json:"case_timeline"`
	CaseEvidenceHistory    int64 `json:"case_evidence_history"`
	SharedObservations     int64 `json:"shared_observations"`
	SharedHistory          int64 `json:"shared_history"`
	SharedReviews          int64 `json:"shared_reviews"`
	SharedGeneratedRouters int64 `json:"shared_generated_router_facts"`
}

// ResetSharedRiskTestData removes only derived shared-risk state. The guards
// intentionally cover the whole test installation: once an operator has added
// a comment/label or any action exists, an automatic destructive reset is no
// longer safe.
func (s *PostgresStore) ResetSharedRiskTestData(ctx context.Context) (SharedRiskResetReport, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return SharedRiskResetReport{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations'))`); err != nil {
		return SharedRiskResetReport{}, err
	}
	var actions, comments, labels int64
	if err = tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM enforcement_actions),
 (SELECT count(*) FROM risk_case_comments),
 (SELECT count(*) FROM labels)`).Scan(&actions, &comments, &labels); err != nil {
		return SharedRiskResetReport{}, err
	}
	if actions != 0 || comments != 0 || labels != 0 {
		return SharedRiskResetReport{}, fmt.Errorf("refuse shared risk reset: enforcement_actions=%d case_comments=%d labels=%d", actions, comments, labels)
	}
	report := SharedRiskResetReport{}
	count := func(target *int64, query string) error {
		result, execErr := tx.ExecContext(ctx, query)
		if execErr != nil {
			return execErr
		}
		*target, _ = result.RowsAffected()
		return nil
	}
	if err = tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM risk_case_timeline),
 (SELECT count(*) FROM risk_case_evidence_snapshots),
 (SELECT count(*) FROM shared_behavior_observation_history)`).Scan(&report.CaseTimeline, &report.CaseEvidenceHistory, &report.SharedHistory); err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TEMP TABLE reset_shared_router_assessments ON COMMIT DROP AS
SELECT DISTINCT f.assessment_id FROM router_evidence_facts f
WHERE f.source_family='shared_gateway_behavior'
AND NOT EXISTS(SELECT 1 FROM router_evidence_facts independent WHERE independent.assessment_id=f.assessment_id AND independent.source_family<>'shared_gateway_behavior')`); err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, `TRUNCATE TABLE risk_case_evidence_snapshots,risk_case_timeline RESTART IDENTITY`); err != nil {
		return report, err
	}
	if err = count(&report.Cases, `DELETE FROM risk_cases`); err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, `TRUNCATE TABLE shared_manual_disconnect_grants,shared_access_review_conclusions,shared_access_review_executions,shared_access_review_evidence RESTART IDENTITY`); err != nil {
		return report, err
	}
	if err = count(&report.SharedReviews, `DELETE FROM shared_access_reviews`); err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, `TRUNCATE TABLE risk_snapshot_history,subject_risk_snapshot_history RESTART IDENTITY`); err != nil {
		return report, err
	}
	if err = count(&report.RiskSnapshots, `DELETE FROM risk_snapshots`); err != nil {
		return report, err
	}
	var subjectRiskSnapshots int64
	if err = count(&subjectRiskSnapshots, `DELETE FROM subject_risk_snapshots`); err != nil {
		return report, err
	}
	report.RiskSnapshots += subjectRiskSnapshots
	if _, err = tx.ExecContext(ctx, `TRUNCATE TABLE shared_behavior_observation_history RESTART IDENTITY`); err != nil {
		return report, err
	}
	if err = count(&report.SharedObservations, `DELETE FROM shared_behavior_observations`); err != nil {
		return report, err
	}
	for _, query := range []string{`DELETE FROM shared_behavior_generations`, `DELETE FROM evidence WHERE type='shared_access_window'`, `DELETE FROM read_model_runtime_state WHERE name='shared-behavior'`} {
		if _, err = tx.ExecContext(ctx, query); err != nil {
			return report, err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM router_assessment_history WHERE assessment_id IN(SELECT assessment_id FROM reset_shared_router_assessments)`); err != nil {
		return report, err
	}
	if err = count(&report.SharedGeneratedRouters, `DELETE FROM router_evidence_facts WHERE source_family='shared_gateway_behavior'`); err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM router_assessments WHERE assessment_id IN(SELECT assessment_id FROM reset_shared_router_assessments)`); err != nil {
		return report, err
	}
	if err = tx.Commit(); err != nil {
		return report, err
	}
	return report, nil
}
