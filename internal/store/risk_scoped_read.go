package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

// GetStreamRiskSnapshot is the narrow current-state read for one sensor and
// subject. Read cutover will choose this source only after all enabled inputs
// and the risk projection have passed their independent confirmation gates.
func (s *DBStore) GetStreamRiskSnapshot(ctx context.Context, sensor, subjectType, subjectID string) (risk.Snapshot, bool, error) {
	if s == nil || s.pg == nil {
		return risk.Snapshot{}, false, errors.New("scoped risk reader unavailable")
	}
	return s.pg.GetStreamRiskSnapshot(ctx, sensor, subjectType, subjectID)
}

func (s *PostgresStore) GetStreamRiskSnapshot(ctx context.Context, sensor, subjectType, subjectID string) (risk.Snapshot, bool, error) {
	if s == nil || s.db == nil || sensor == "" || subjectID == "" || (subjectType != "ip" && subjectType != "account") {
		return risk.Snapshot{}, false, errors.New("invalid scoped risk read")
	}
	var raw []byte
	var observed time.Time
	var storedHash string
	err := s.db.QueryRowContext(ctx, `SELECT snapshot,observed_at,content_sha256 FROM stream_risk_current c
 WHERE c.sensor_id=$1 AND c.subject_type=$2 AND c.subject_id=$3
 AND c.evaluated_at>=(SELECT max(accepted_after) FROM stream_risk_fresh_cutovers WHERE sensor_id=c.sensor_id)`, sensor, subjectType, subjectID).Scan(&raw, &observed, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return risk.Snapshot{}, false, nil
	}
	if err != nil {
		return risk.Snapshot{}, false, err
	}
	var item risk.Snapshot
	if err := json.Unmarshal(raw, &item); err != nil {
		return risk.Snapshot{}, false, err
	}
	identity := item.SubjectID
	if subjectType == "ip" {
		identity = item.IP
	}
	stamp, err := time.Parse(time.RFC3339Nano, item.UpdatedAt)
	if err != nil || identity != subjectID || !stamp.Equal(observed.UTC()) {
		return risk.Snapshot{}, false, errors.New("scoped risk snapshot identity or observation conflict")
	}
	semantic := item
	semantic.UpdatedAt = ""
	actualHash, err := riskJSONHash(semantic)
	if err != nil || actualHash != storedHash {
		return risk.Snapshot{}, false, errors.New("scoped risk snapshot content conflict")
	}
	return item, true, nil
}

// ListStreamRiskEvidence reads a bounded set of current interpretations for
// one sensor and subject. It never falls back to global legacy evidence.
func (s *PostgresStore) ListStreamRiskEvidence(ctx context.Context, sensor, subjectType, subjectID string, limit int) ([]evidence.Evidence, error) {
	if s == nil || s.db == nil || sensor == "" || subjectID == "" || (subjectType != "ip" && subjectType != "account") || limit < 1 || limit > 100 {
		return nil, errors.New("invalid scoped risk evidence read")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.evidence_id,e.content_sha256,e.evidence FROM stream_risk_evidence e
 WHERE e.sensor_id=$1 AND e.subject_type=$2 AND e.subject_id=$3
 AND e.evaluated_at>=(SELECT max(accepted_after) FROM stream_risk_fresh_cutovers WHERE sensor_id=e.sensor_id)
 ORDER BY e.created_at DESC,e.evidence_id DESC LIMIT $4`, sensor, subjectType, subjectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]evidence.Evidence, 0, limit)
	for rows.Next() {
		var id, expectedHash string
		var raw []byte
		if err := rows.Scan(&id, &expectedHash, &raw); err != nil {
			return nil, err
		}
		var item evidence.Evidence
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		actualHash, err := riskJSONHash(item)
		if err != nil || item.EvidenceID != id || actualHash != expectedHash {
			return nil, fmt.Errorf("scoped risk evidence content conflict: %s", id)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
