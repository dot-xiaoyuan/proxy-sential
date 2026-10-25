package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	"proxy-sentinel/internal/evidence"
)

const (
	evidenceBatchCount = 500
	evidenceBatchBytes = 1 << 20
)

// Separate repeated keys so corrections in one call retain their order.
func partitionEvidence(items []evidence.Evidence) ([][]evidence.Evidence, error) {
	var runs [][]evidence.Evidence
	current := make([]evidence.Evidence, 0, evidenceBatchCount)
	seen := map[string]bool{}
	bytes := 0
	for _, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if len(encoded) > evidenceBatchBytes {
			return nil, fmt.Errorf("evidence exceeds batch byte limit")
		}
		if len(current) > 0 && (seen[item.EvidenceID] || len(current) >= evidenceBatchCount || bytes+len(encoded) > evidenceBatchBytes) {
			runs = append(runs, current)
			current = make([]evidence.Evidence, 0, evidenceBatchCount)
			seen = map[string]bool{}
			bytes = 0
		}
		current = append(current, item)
		seen[item.EvidenceID] = true
		bytes += len(encoded)
	}
	if len(current) > 0 {
		runs = append(runs, current)
	}
	return runs, nil
}

func writeEvidenceSets(ctx context.Context, tx *sql.Tx, items []evidence.Evidence) error {
	ipRows := make([]evidence.Evidence, 0, len(items))
	subjectRows := make([]evidence.Evidence, 0)
	for _, item := range items {
		if item.SubjectType != "" && item.SubjectType != "ip" {
			subjectRows = append(subjectRows, item)
		} else if item.IP != "" {
			ipRows = append(ipRows, item)
		}
	}
	sort.Slice(ipRows, func(i, j int) bool { return ipRows[i].EvidenceID < ipRows[j].EvidenceID })
	sort.Slice(subjectRows, func(i, j int) bool { return subjectRows[i].EvidenceID < subjectRows[j].EvidenceID })
	if len(ipRows) > 0 {
		encoded, err := json.Marshal(ipRows)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, upsertIPEvidenceBatchSQL, encoded); err != nil {
			return err
		}
	}
	if len(subjectRows) > 0 {
		encoded, err := json.Marshal(subjectRows)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, upsertSubjectEvidenceBatchSQL, encoded); err != nil {
			return err
		}
	}
	return nil
}

const upsertIPEvidenceBatchSQL = `WITH rows AS (
 SELECT src.docrow AS doc FROM jsonb_array_elements($1::jsonb) AS src(docrow)
)
INSERT INTO evidence(evidence_id,ip,type,"window",score,confidence,severity,reason,samples,created_at,metadata)
SELECT doc->>'evidence_id',(doc->>'ip')::inet,doc->>'type',doc->>'window',(doc->>'score')::integer,(doc->>'confidence')::double precision,doc->>'severity',doc->>'reason',doc->'samples',(doc->>'created_at')::timestamptz,
 CASE WHEN doc ? 'shared_access' THEN jsonb_build_object('shared_access',doc->'shared_access') ELSE '{}'::jsonb END
FROM rows
ON CONFLICT(evidence_id) DO UPDATE SET score=EXCLUDED.score,confidence=EXCLUDED.confidence,severity=EXCLUDED.severity,reason=EXCLUDED.reason,samples=EXCLUDED.samples,metadata=EXCLUDED.metadata
WHERE (evidence.score,evidence.confidence,evidence.severity,evidence.reason,evidence.samples,evidence.metadata)
 IS DISTINCT FROM (EXCLUDED.score,EXCLUDED.confidence,EXCLUDED.severity,EXCLUDED.reason,EXCLUDED.samples,EXCLUDED.metadata)`

const upsertSubjectEvidenceBatchSQL = `WITH rows AS (
 SELECT src.docrow AS doc FROM jsonb_array_elements($1::jsonb) AS src(docrow)
)
INSERT INTO subject_evidence(evidence_id,subject_type,subject_id,account_id,endpoint_id,ip,type,"window",score,confidence,severity,reason,samples,created_at)
SELECT doc->>'evidence_id',doc->>'subject_type',doc->>'subject_id',COALESCE(doc->>'account_id',''),COALESCE(doc->>'endpoint_id',''),NULLIF(doc->>'ip','')::inet,doc->>'type',doc->>'window',(doc->>'score')::integer,(doc->>'confidence')::double precision,doc->>'severity',doc->>'reason',doc->'samples',(doc->>'created_at')::timestamptz
FROM rows
ON CONFLICT(evidence_id) DO UPDATE SET score=EXCLUDED.score,confidence=EXCLUDED.confidence,severity=EXCLUDED.severity,reason=EXCLUDED.reason,samples=EXCLUDED.samples
WHERE (subject_evidence.score,subject_evidence.confidence,subject_evidence.severity,subject_evidence.reason,subject_evidence.samples)
 IS DISTINCT FROM (EXCLUDED.score,EXCLUDED.confidence,EXCLUDED.severity,EXCLUDED.reason,EXCLUDED.samples)`
