package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	"proxy-sentinel/internal/risk"
)

const (
	riskSnapshotBatchCount = 500
	riskSnapshotBatchBytes = 1 << 20
)

// A batch has at most one interpretation per subject. If a replay supplies
// multiple transitions for the same subject, flush before the next one so the
// history and current-state ordering remain the same as individual writes.
func partitionRiskSnapshots(items []risk.Snapshot) ([][]risk.Snapshot, error) {
	var runs [][]risk.Snapshot
	current := make([]risk.Snapshot, 0, riskSnapshotBatchCount)
	seen := map[string]bool{}
	bytes := 0
	for _, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if len(encoded) > riskSnapshotBatchBytes {
			return nil, fmt.Errorf("risk snapshot exceeds batch byte limit")
		}
		key := "ip:" + item.IP
		if item.SubjectType != "" && item.SubjectType != "ip" {
			key = item.SubjectType + ":" + item.SubjectID
		}
		if len(current) > 0 && (seen[key] || len(current) >= riskSnapshotBatchCount || bytes+len(encoded) > riskSnapshotBatchBytes) {
			runs = append(runs, current)
			current = make([]risk.Snapshot, 0, riskSnapshotBatchCount)
			seen = map[string]bool{}
			bytes = 0
		}
		current = append(current, item)
		seen[key] = true
		bytes += len(encoded)
	}
	if len(current) > 0 {
		runs = append(runs, current)
	}
	return runs, nil
}

type riskSnapshotBatchRow struct {
	SubjectType string        `json:"subject_type"`
	SubjectID   string        `json:"subject_id"`
	IP          string        `json:"ip"`
	Snapshot    risk.Snapshot `json:"snapshot"`
}

func writeRiskSnapshotSets(ctx context.Context, tx *sql.Tx, items []risk.Snapshot) error {
	ipRows := make([]riskSnapshotBatchRow, 0, len(items))
	subjectRows := make([]riskSnapshotBatchRow, 0)
	for _, item := range items {
		if item.SubjectType != "" && item.SubjectType != "ip" {
			subjectRows = append(subjectRows, riskSnapshotBatchRow{SubjectType: item.SubjectType, SubjectID: item.SubjectID, IP: item.IP, Snapshot: item})
		} else if item.IP != "" {
			ipRows = append(ipRows, riskSnapshotBatchRow{SubjectType: "ip", SubjectID: item.IP, IP: item.IP, Snapshot: item})
		}
	}
	sort.Slice(ipRows, func(i, j int) bool { return ipRows[i].IP < ipRows[j].IP })
	sort.Slice(subjectRows, func(i, j int) bool {
		if subjectRows[i].SubjectType != subjectRows[j].SubjectType {
			return subjectRows[i].SubjectType < subjectRows[j].SubjectType
		}
		return subjectRows[i].SubjectID < subjectRows[j].SubjectID
	})
	if len(ipRows) > 0 {
		encoded, err := json.Marshal(ipRows)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, upsertIPRiskSnapshotBatchSQL, encoded); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, appendIPRiskSnapshotHistoryBatchSQL, encoded); err != nil {
			return err
		}
	}
	if len(subjectRows) > 0 {
		encoded, err := json.Marshal(subjectRows)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, upsertSubjectRiskSnapshotBatchSQL, encoded); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, appendSubjectRiskSnapshotHistoryBatchSQL, encoded); err != nil {
			return err
		}
	}
	return nil
}

const upsertIPRiskSnapshotBatchSQL = `WITH rows AS (
 SELECT src.docrow->>'ip' AS ip,src.docrow->'snapshot' AS doc FROM jsonb_array_elements($1::jsonb) AS src(docrow)
)
INSERT INTO risk_snapshots(ip,score,level,confidence,"window",evidence_ids,summary,recommended_action,updated_at,assessment_level,review_disposition,automation_eligible,automation_blockers,detection_basis,independent_signal_groups)
SELECT ip::inet,(doc->>'score')::integer,doc->>'level',(doc->>'confidence')::double precision,doc->>'window',doc->'evidence_ids',doc->>'summary',doc->>'recommended_action',(doc->>'updated_at')::timestamptz,doc->>'assessment_level',NULLIF(doc->>'review_disposition',''),(doc->>'automation_eligible')::boolean,COALESCE(doc->'automation_blockers','null'::jsonb),doc->>'detection_basis',COALESCE(doc->'independent_signal_groups','null'::jsonb)
FROM rows
ON CONFLICT(ip) DO UPDATE SET score=EXCLUDED.score,level=EXCLUDED.level,confidence=EXCLUDED.confidence,"window"=EXCLUDED."window",evidence_ids=EXCLUDED.evidence_ids,summary=EXCLUDED.summary,recommended_action=EXCLUDED.recommended_action,updated_at=EXCLUDED.updated_at,assessment_level=EXCLUDED.assessment_level,review_disposition=COALESCE(NULLIF(risk_snapshots.review_disposition,''),EXCLUDED.review_disposition),automation_eligible=EXCLUDED.automation_eligible,automation_blockers=EXCLUDED.automation_blockers,detection_basis=EXCLUDED.detection_basis,independent_signal_groups=EXCLUDED.independent_signal_groups
WHERE risk_snapshots.updated_at<=EXCLUDED.updated_at AND
 (risk_snapshots.score,risk_snapshots.level,risk_snapshots.confidence,risk_snapshots."window",risk_snapshots.evidence_ids,risk_snapshots.summary,risk_snapshots.recommended_action,risk_snapshots.updated_at,risk_snapshots.assessment_level,risk_snapshots.review_disposition,risk_snapshots.automation_eligible,risk_snapshots.automation_blockers,risk_snapshots.detection_basis,risk_snapshots.independent_signal_groups)
 IS DISTINCT FROM
 (EXCLUDED.score,EXCLUDED.level,EXCLUDED.confidence,EXCLUDED."window",EXCLUDED.evidence_ids,EXCLUDED.summary,EXCLUDED.recommended_action,EXCLUDED.updated_at,EXCLUDED.assessment_level,COALESCE(NULLIF(risk_snapshots.review_disposition,''),EXCLUDED.review_disposition),EXCLUDED.automation_eligible,EXCLUDED.automation_blockers,EXCLUDED.detection_basis,EXCLUDED.independent_signal_groups)`

const appendIPRiskSnapshotHistoryBatchSQL = `WITH rows AS (
 SELECT src.docrow->>'ip' AS ip,src.docrow->'snapshot' AS doc FROM jsonb_array_elements($1::jsonb) AS src(docrow)
), changed AS (
 INSERT INTO risk_snapshot_history_heads(subject_type,subject_id,snapshot_hash)
 SELECT 'ip',ip,md5(doc::text) FROM rows
 ON CONFLICT(subject_type,subject_id) DO UPDATE SET snapshot_hash=EXCLUDED.snapshot_hash,changed_at=now()
 WHERE risk_snapshot_history_heads.snapshot_hash IS DISTINCT FROM EXCLUDED.snapshot_hash
 RETURNING subject_id
)
INSERT INTO risk_snapshot_history(ip,snapshot)
SELECT rows.ip::inet,rows.doc FROM rows JOIN changed ON changed.subject_id=rows.ip`

const upsertSubjectRiskSnapshotBatchSQL = `WITH rows AS (
 SELECT src.docrow->>'subject_type' AS subject_type,src.docrow->>'subject_id' AS subject_id,src.docrow->>'ip' AS ip,src.docrow->'snapshot' AS doc FROM jsonb_array_elements($1::jsonb) AS src(docrow)
)
INSERT INTO subject_risk_snapshots(subject_type,subject_id,account_id,endpoint_id,ip,score,level,confidence,"window",evidence_ids,summary,recommended_action,updated_at,assessment_level,review_disposition,automation_eligible,automation_blockers,detection_basis,independent_signal_groups)
SELECT subject_type,subject_id,COALESCE(doc->>'account_id',''),COALESCE(doc->>'endpoint_id',''),NULLIF(ip,'')::inet,(doc->>'score')::integer,doc->>'level',(doc->>'confidence')::double precision,doc->>'window',doc->'evidence_ids',doc->>'summary',doc->>'recommended_action',(doc->>'updated_at')::timestamptz,doc->>'assessment_level',NULLIF(doc->>'review_disposition',''),(doc->>'automation_eligible')::boolean,COALESCE(doc->'automation_blockers','null'::jsonb),doc->>'detection_basis',COALESCE(doc->'independent_signal_groups','null'::jsonb)
FROM rows
ON CONFLICT(subject_type,subject_id) DO UPDATE SET account_id=EXCLUDED.account_id,endpoint_id=EXCLUDED.endpoint_id,ip=EXCLUDED.ip,score=EXCLUDED.score,level=EXCLUDED.level,confidence=EXCLUDED.confidence,"window"=EXCLUDED."window",evidence_ids=EXCLUDED.evidence_ids,summary=EXCLUDED.summary,recommended_action=EXCLUDED.recommended_action,updated_at=EXCLUDED.updated_at,assessment_level=EXCLUDED.assessment_level,review_disposition=COALESCE(NULLIF(subject_risk_snapshots.review_disposition,''),EXCLUDED.review_disposition),automation_eligible=EXCLUDED.automation_eligible,automation_blockers=EXCLUDED.automation_blockers,detection_basis=EXCLUDED.detection_basis,independent_signal_groups=EXCLUDED.independent_signal_groups
WHERE subject_risk_snapshots.updated_at<=EXCLUDED.updated_at AND
 (subject_risk_snapshots.account_id,subject_risk_snapshots.endpoint_id,subject_risk_snapshots.ip,subject_risk_snapshots.score,subject_risk_snapshots.level,subject_risk_snapshots.confidence,subject_risk_snapshots."window",subject_risk_snapshots.evidence_ids,subject_risk_snapshots.summary,subject_risk_snapshots.recommended_action,subject_risk_snapshots.updated_at,subject_risk_snapshots.assessment_level,subject_risk_snapshots.review_disposition,subject_risk_snapshots.automation_eligible,subject_risk_snapshots.automation_blockers,subject_risk_snapshots.detection_basis,subject_risk_snapshots.independent_signal_groups)
 IS DISTINCT FROM
 (EXCLUDED.account_id,EXCLUDED.endpoint_id,EXCLUDED.ip,EXCLUDED.score,EXCLUDED.level,EXCLUDED.confidence,EXCLUDED."window",EXCLUDED.evidence_ids,EXCLUDED.summary,EXCLUDED.recommended_action,EXCLUDED.updated_at,EXCLUDED.assessment_level,COALESCE(NULLIF(subject_risk_snapshots.review_disposition,''),EXCLUDED.review_disposition),EXCLUDED.automation_eligible,EXCLUDED.automation_blockers,EXCLUDED.detection_basis,EXCLUDED.independent_signal_groups)`

const appendSubjectRiskSnapshotHistoryBatchSQL = `WITH rows AS (
 SELECT src.docrow->>'subject_type' AS subject_type,src.docrow->>'subject_id' AS subject_id,src.docrow->'snapshot' AS doc FROM jsonb_array_elements($1::jsonb) AS src(docrow)
), changed AS (
 INSERT INTO risk_snapshot_history_heads(subject_type,subject_id,snapshot_hash)
 SELECT subject_type,subject_id,md5(doc::text) FROM rows
 ON CONFLICT(subject_type,subject_id) DO UPDATE SET snapshot_hash=EXCLUDED.snapshot_hash,changed_at=now()
 WHERE risk_snapshot_history_heads.snapshot_hash IS DISTINCT FROM EXCLUDED.snapshot_hash
 RETURNING subject_type,subject_id
)
INSERT INTO subject_risk_snapshot_history(subject_type,subject_id,snapshot)
SELECT rows.subject_type,rows.subject_id,rows.doc FROM rows JOIN changed USING(subject_type,subject_id)`
