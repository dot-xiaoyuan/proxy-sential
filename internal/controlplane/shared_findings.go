package controlplane

import (
	"context"
	"database/sql"
	"slices"

	"proxy-sentinel/internal/sharedaccess"
)

// Only reportable observations enter the time index. Direct activity with no
// sharing clue still wakes its outlet but never becomes a sharing candidate.
func recordSharedFinding(ctx context.Context, tx *sql.Tx, item sharedaccess.BehaviorAssessment, d sharedaccess.ObservationDecision) error {
	if !item.Current {
		return nil
	}
	g := item.SignalGroups
	if !slices.Contains(g, "router_identity") && !slices.Contains(g, "ieee1905_association") && !(slices.Contains(g, "ttl_path") && slices.Contains(g, "tls_stack")) {
		return nil
	}
	outcome := "candidate"
	switch {
	case item.Exemption != nil:
		outcome = "exempt"
	case item.Status == "confirmed" && d.Result == "matched" && d.AccountID != "":
		outcome = "confirmed"
	case item.AccountID == "":
		outcome = "unattributed"
	case item.Router.AssessmentID != "":
		outcome = "router_pending"
	}
	caseID, actionID := "", ""
	if outcome == "confirmed" {
		caseID = d.CaseID
		if violationObservationOnly() {
			actionID = "shared-record:" + d.ExecutionID
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO shared_access_findings(observation_id,sensor_id,campus_id,access_domain,ip,observed_at,account_id,outcome,basis,reason,case_id,action_id,case_pending)
 VALUES($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10,$11,$12,$11<>'')
 ON CONFLICT(observation_id) DO UPDATE SET account_id=EXCLUDED.account_id,outcome=EXCLUDED.outcome,basis=EXCLUDED.basis,
 reason=EXCLUDED.reason,case_id=EXCLUDED.case_id,action_id=EXCLUDED.action_id,case_pending=EXCLUDED.case_pending
 WHERE (shared_access_findings.account_id,shared_access_findings.outcome,shared_access_findings.basis,shared_access_findings.reason,shared_access_findings.case_id)
 IS DISTINCT FROM (EXCLUDED.account_id,EXCLUDED.outcome,EXCLUDED.basis,EXCLUDED.reason,EXCLUDED.case_id)`, item.ObservationID, item.SensorID, item.CampusID, item.AccessDomain, item.IP, item.LastSeen, item.AccountID, outcome, item.ConfirmationBasis, item.ReviewReason, caseID, actionID)
	return err
}
