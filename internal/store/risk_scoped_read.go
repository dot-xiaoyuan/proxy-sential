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

type StreamRiskSubjectState struct {
	State         string         `json:"state"`
	AcceptedAfter *time.Time     `json:"accepted_after,omitempty"`
	PendingSince  *time.Time     `json:"pending_since,omitempty"`
	Snapshot      *risk.Snapshot `json:"snapshot,omitempty"`
}

func (s *DBStore) GetStreamRiskSubjectState(ctx context.Context, sensor, subjectType, subjectID string) (StreamRiskSubjectState, error) {
	if s == nil || s.pg == nil {
		return StreamRiskSubjectState{}, errors.New("scoped risk state store unavailable")
	}
	return s.pg.GetStreamRiskSubjectState(ctx, sensor, subjectType, subjectID)
}

// The single statement reads the latest cutover, pending generation and
// current interpretation from one PostgreSQL snapshot. A queued newer input
// takes precedence over a previously evaluated interpretation.
func (s *PostgresStore) GetStreamRiskSubjectState(ctx context.Context, sensor, subjectType, subjectID string) (StreamRiskSubjectState, error) {
	if s == nil || s.db == nil || sensor == "" || subjectID == "" || (subjectType != "ip" && subjectType != "account") {
		return StreamRiskSubjectState{}, errors.New("invalid scoped risk state lookup")
	}
	var cutoff time.Time
	var pending, observed sql.NullTime
	var raw []byte
	var hash sql.NullString
	err := s.db.QueryRowContext(ctx, `WITH cut AS (
 SELECT accepted_after FROM stream_risk_fresh_cutovers WHERE sensor_id=$1 ORDER BY accepted_after DESC LIMIT 1
)
SELECT cut.accepted_after,q.first_dirty_at,c.snapshot,c.observed_at,c.content_sha256
FROM cut
LEFT JOIN risk_feature_dirty_subjects q ON q.sensor_id=$1 AND q.subject_type=$2 AND q.subject_id=$3
LEFT JOIN stream_risk_current c ON c.sensor_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND c.evaluated_at>=cut.accepted_after`,
		sensor, subjectType, subjectID).Scan(&cutoff, &pending, &raw, &observed, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return StreamRiskSubjectState{State: "not_started"}, nil
	}
	if err != nil {
		return StreamRiskSubjectState{}, err
	}
	cutoff = cutoff.UTC()
	state := StreamRiskSubjectState{AcceptedAfter: &cutoff}
	if pending.Valid {
		since := pending.Time.UTC()
		if since.Before(cutoff) {
			since = cutoff
		}
		state.State, state.PendingSince = "processing", &since
		return state, nil
	}
	if len(raw) == 0 {
		state.State = "no_record"
		return state, nil
	}
	if !observed.Valid || !hash.Valid {
		return StreamRiskSubjectState{}, errors.New("scoped risk state has incomplete current result")
	}
	snapshot, err := parseScopedRiskSnapshot(raw, observed.Time, hash.String, subjectType, subjectID)
	if err != nil {
		return StreamRiskSubjectState{}, err
	}
	if observed.Time.Before(time.Now().UTC().Add(-10 * time.Minute)) {
		state.State = "expired"
		return state, nil
	}
	state.State, state.Snapshot = "current", &snapshot
	return state, nil
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
 AND c.evaluated_at>=(SELECT max(accepted_after) FROM stream_risk_fresh_cutovers WHERE sensor_id=c.sensor_id)
 AND c.observed_at>=now()-interval '10 minutes'
 AND NOT EXISTS (SELECT 1 FROM risk_feature_dirty_subjects q
                 WHERE q.sensor_id=c.sensor_id AND q.subject_type=c.subject_type AND q.subject_id=c.subject_id)`, sensor, subjectType, subjectID).Scan(&raw, &observed, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return risk.Snapshot{}, false, nil
	}
	if err != nil {
		return risk.Snapshot{}, false, err
	}
	item, err := parseScopedRiskSnapshot(raw, observed, storedHash, subjectType, subjectID)
	return item, err == nil, err
}

func parseScopedRiskSnapshot(raw []byte, observed time.Time, storedHash, subjectType, subjectID string) (risk.Snapshot, error) {
	var item risk.Snapshot
	if err := json.Unmarshal(raw, &item); err != nil {
		return risk.Snapshot{}, err
	}
	identity := item.SubjectID
	if subjectType == "ip" {
		identity = item.IP
	}
	stamp, err := time.Parse(time.RFC3339Nano, item.UpdatedAt)
	if err != nil || identity != subjectID || !stamp.Equal(observed.UTC()) {
		return risk.Snapshot{}, errors.New("scoped risk snapshot identity or observation conflict")
	}
	semantic := item
	semantic.UpdatedAt = ""
	actualHash, err := riskJSONHash(semantic)
	if err != nil || actualHash != storedHash {
		return risk.Snapshot{}, errors.New("scoped risk snapshot content conflict")
	}
	return item, nil
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
